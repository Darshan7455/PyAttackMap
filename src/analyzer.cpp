#include "pyattackmap/analyzer.hpp"

#include <chrono>
#include <future>
#include <mutex>
#include <thread>
#include <algorithm>

#include "pyattackmap/exceptions.hpp"
#include "pyattackmap/parser.hpp"

namespace pyattackmap {

static bool glob_match(std::string_view text, std::string_view pat) {
    size_t t = 0, p = 0;
    size_t star_p = std::string_view::npos, match_t = 0;
    while (t < text.size()) {
        if (p < pat.size() && (pat[p] == '?' || pat[p] == text[t])) {
            ++t;
            ++p;
        } else if (p < pat.size() && pat[p] == '*') {
            star_p = p++;
            match_t = t;
        } else if (star_p != std::string_view::npos) {
            p = star_p + 1;
            t = ++match_t;
        } else {
            return false;
        }
    }
    while (p < pat.size() && pat[p] == '*') {
        ++p;
    }
    return p == pat.size();
}

bool Analyzer::should_exclude(std::string_view rel_path, const std::vector<std::string>& patterns) {
    if (patterns.empty()) return false;

    std::string norm(rel_path);
    for (char& c : norm) {
        if (c == '\\') c = '/';
    }

    std::vector<std::string> parts;
    parts.reserve(8);
    size_t start = 0;
    while (start < norm.size()) {
        size_t end = norm.find('/', start);
        if (end == std::string::npos) {
            parts.push_back(norm.substr(start));
            break;
        }
        parts.push_back(norm.substr(start, end - start));
        start = end + 1;
    }
    std::string filename = parts.empty() ? norm : parts.back();

    for (const auto& pattern : patterns) {
        std::string pat = pattern;
        for (char& c : pat) {
            if (c == '\\') c = '/';
        }
        while (!pat.empty() && pat.back() == '/') {
            pat.pop_back();
        }
        if (pat.empty()) continue;

        // Direct segment match
        for (const auto& part : parts) {
            if (part == pat) return true;
        }

        // Full relative path match
        if (glob_match(norm, pat) ||
            glob_match(norm, "*/" + pat + "/*") ||
            glob_match(norm, pat + "/*") ||
            glob_match(norm, "*/" + pat)) {
            return true;
        }

        // Filename match
        if (glob_match(filename, pat)) {
            return true;
        }
    }

    return false;
}

std::vector<std::filesystem::path>
Analyzer::discover_python_files(const std::filesystem::path& target, const ScanConfig& config) {
    std::error_code ec;
    if (!std::filesystem::exists(target, ec)) {
        throw FileAccessException("Target path does not exist: " + target.string());
    }

    std::filesystem::path base = std::filesystem::canonical(target, ec);
    if (ec) base = std::filesystem::absolute(target);

    if (std::filesystem::is_regular_file(base)) {
        std::string ext = base.extension().string();
        for (char& c : ext) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

        if (ext == ".py" || ext.empty()) {
            if (!should_exclude(base.filename().string(), config.exclude)) {
                return {base};
            }
        }
        return {};
    }

    std::vector<std::filesystem::path> discovered;
    discovered.reserve(128);
    std::filesystem::recursive_directory_iterator it(base, std::filesystem::directory_options::skip_permission_denied, ec);
    std::filesystem::recursive_directory_iterator end;

    while (it != end) {
        const auto& entry = *it;
        std::string rel;
        try {
            rel = std::filesystem::relative(entry.path(), base).string();
        } catch (...) {
            rel = entry.path().filename().string();
        }

        if (entry.is_directory()) {
            if (should_exclude(rel, config.exclude)) {
                it.disable_recursion_pending();
            }
        } else if (entry.is_regular_file()) {
            std::string ext = entry.path().extension().string();
            for (char& c : ext) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

            if (ext == ".py") {
                if (!should_exclude(rel, config.exclude)) {
                    discovered.push_back(entry.path());
                }
            }
        }

        it.increment(ec);
        if (ec) {
            break;
        }
    }

    std::sort(discovered.begin(), discovered.end());
    return discovered;
}

Analyzer::Analyzer(ScanConfig config, RuleRegistry* registry)
    : config_(std::move(config)),
      registry_(registry ? registry : &RuleRegistry::default_registry()) {}

AnalysisResult Analyzer::scan(const std::filesystem::path& target) const {
    if (target.empty()) {
        throw ConfigException("Target path must not be empty");
    }

    auto start_time = std::chrono::steady_clock::now();
    std::vector<std::filesystem::path> files = discover_python_files(target, config_);

    std::vector<Finding> all_findings;
    all_findings.reserve(files.size() * 2);
    std::vector<AnalysisError> all_errors;
    size_t parse_errors_count = 0;

    auto rules = registry_->get_enabled_rules(config_);

    unsigned int num_threads = config_.jobs;
    if (num_threads == 0) {
        num_threads = std::thread::hardware_concurrency();
        if (num_threads == 0) num_threads = 1;
    }

    if (num_threads > 1 && files.size() > 4) {
        std::mutex mtx;
        size_t total_files = files.size();
        size_t batch_size = (total_files + num_threads - 1) / num_threads;
        std::vector<std::future<void>> futures;

        for (size_t t = 0; t < num_threads; ++t) {
            size_t start_idx = t * batch_size;
            size_t end_idx = std::min(start_idx + batch_size, total_files);
            if (start_idx >= total_files) break;

            futures.push_back(std::async(std::launch::async, [&, start_idx, end_idx]() {
                auto worker_parser = SafeParser::make_parser();

                std::vector<Finding> local_findings;
                std::vector<AnalysisError> local_errors;
                size_t local_parse_errors = 0;

                for (size_t i = start_idx; i < end_idx; ++i) {
                    const auto& file_path = files[i];
                    try {
                        ParsedSource parsed = SafeParser::parse_file(file_path, config_.max_file_size_kb, worker_parser.get());
                        for (const auto& rule : rules) {
                            try {
                                auto rf = rule->run(parsed, config_);
                                for (auto& f : rf) {
                                    if (static_cast<uint8_t>(f.severity) >= static_cast<uint8_t>(config_.min_severity)) {
                                        local_findings.push_back(std::move(f));
                                    }
                                }
                            } catch (const std::exception& rex) {
                                local_errors.push_back(AnalysisError{
                                    .file = file_path.string(),
                                    .error_type = "RuleExecutionError",
                                    .message = std::string("Rule ") + std::string(rule->rule_id()) + " failed: " + rex.what(),
                                    .line = std::nullopt
                                });
                            }
                        }
                    } catch (const ParseException& pe) {
                        ++local_parse_errors;
                        local_errors.push_back(AnalysisError{
                            .file = pe.file_path(),
                            .error_type = "ParseError",
                            .message = pe.what(),
                            .line = pe.line()
                        });
                    } catch (const FileAccessException& fae) {
                        local_errors.push_back(AnalysisError{
                            .file = file_path.string(),
                            .error_type = "FileAccessError",
                            .message = fae.what(),
                            .line = std::nullopt
                        });
                    } catch (const std::exception& ex) {
                        local_errors.push_back(AnalysisError{
                            .file = file_path.string(),
                            .error_type = "UnexpectedError",
                            .message = ex.what(),
                            .line = std::nullopt
                        });
                    }
                }

                std::lock_guard<std::mutex> lock(mtx);
                all_findings.insert(all_findings.end(),
                                    std::make_move_iterator(local_findings.begin()),
                                    std::make_move_iterator(local_findings.end()));
                all_errors.insert(all_errors.end(),
                                  std::make_move_iterator(local_errors.begin()),
                                  std::make_move_iterator(local_errors.end()));
                parse_errors_count += local_parse_errors;
            }));
        }

        for (auto& f : futures) {
            f.get();
        }
    } else {
        auto local_parser = SafeParser::make_parser();

        for (const auto& file_path : files) {
            try {
                ParsedSource parsed = SafeParser::parse_file(file_path, config_.max_file_size_kb, local_parser.get());
                for (const auto& rule : rules) {
                    try {
                        auto rf = rule->run(parsed, config_);
                        for (auto& f : rf) {
                            if (static_cast<uint8_t>(f.severity) >= static_cast<uint8_t>(config_.min_severity)) {
                                all_findings.push_back(std::move(f));
                            }
                        }
                    } catch (const std::exception& rex) {
                        all_errors.push_back(AnalysisError{
                            .file = file_path.string(),
                            .error_type = "RuleExecutionError",
                            .message = std::string("Rule ") + std::string(rule->rule_id()) + " failed: " + rex.what(),
                            .line = std::nullopt
                        });
                    }
                }
            } catch (const ParseException& pe) {
                ++parse_errors_count;
                all_errors.push_back(AnalysisError{
                    .file = pe.file_path(),
                    .error_type = "ParseError",
                    .message = pe.what(),
                    .line = pe.line()
                });
            } catch (const FileAccessException& fae) {
                all_errors.push_back(AnalysisError{
                    .file = file_path.string(),
                    .error_type = "FileAccessError",
                    .message = fae.what(),
                    .line = std::nullopt
                });
            } catch (const std::exception& ex) {
                all_errors.push_back(AnalysisError{
                    .file = file_path.string(),
                    .error_type = "UnexpectedError",
                    .message = ex.what(),
                    .line = std::nullopt
                });
            }
        }
    }

    // Deduplicate findings by ID
    std::unordered_map<std::string, Finding> deduped;
    deduped.reserve(all_findings.size());
    for (auto& f : all_findings) {
        deduped.emplace(f.id, std::move(f));
    }

    std::vector<Finding> sorted_findings;
    sorted_findings.reserve(deduped.size());
    for (auto& [_, f] : deduped) {
        sorted_findings.push_back(std::move(f));
    }

    // Stable sort: file, line, col
    std::sort(sorted_findings.begin(), sorted_findings.end(), [](const Finding& a, const Finding& b) {
        if (a.location.file != b.location.file) return a.location.file < b.location.file;
        if (a.location.line != b.location.line) return a.location.line < b.location.line;
        return a.location.col < b.location.col;
    });

    auto end_time = std::chrono::steady_clock::now();
    double duration = std::chrono::duration<double>(end_time - start_time).count();

    ScanStatistics stats;
    stats.files_scanned = files.size();
    stats.files_skipped = 0;
    stats.parse_errors = parse_errors_count;
    stats.total_findings = sorted_findings.size();
    stats.duration_seconds = duration;

    for (const auto& f : sorted_findings) {
        stats.findings_by_severity[to_string(f.severity)]++;
    }

    return AnalysisResult(std::move(sorted_findings), stats, std::move(all_errors));
}

AnalysisResult Analyzer::scan_file(const std::filesystem::path& file_path) const {
    std::error_code ec;
    if (!std::filesystem::is_regular_file(file_path, ec)) {
        throw FileAccessException("File not found: " + file_path.string());
    }
    return scan(file_path);
}

AnalysisResult Analyzer::scan_code(std::string_view code, std::string_view file_path) const {
    auto start_time = std::chrono::steady_clock::now();
    std::vector<Finding> all_findings;
    std::vector<AnalysisError> all_errors;

    ParsedSource parsed;
    try {
        parsed = SafeParser::parse_string(code, file_path);
    } catch (const ParseException& pe) {
        all_errors.push_back(AnalysisError{
            .file = pe.file_path(),
            .error_type = "ParseError",
            .message = pe.what(),
            .line = pe.line()
        });
        ScanStatistics stats;
        stats.files_scanned = 1;
        stats.parse_errors = 1;
        stats.total_findings = 0;
        stats.duration_seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - start_time).count();
        return AnalysisResult({}, stats, std::move(all_errors));
    }

    auto rules = registry_->get_enabled_rules(config_);
    for (const auto& rule : rules) {
        try {
            auto rf = rule->run(parsed, config_);
            for (auto& f : rf) {
                if (static_cast<uint8_t>(f.severity) >= static_cast<uint8_t>(config_.min_severity)) {
                    all_findings.push_back(std::move(f));
                }
            }
        } catch (const std::exception& rex) {
            all_errors.push_back(AnalysisError{
                .file = std::string(file_path),
                .error_type = "RuleExecutionError",
                .message = std::string("Rule ") + std::string(rule->rule_id()) + " failed: " + rex.what(),
                .line = std::nullopt
            });
        }
    }

    std::unordered_map<std::string, Finding> deduped;
    for (auto& f : all_findings) {
        deduped.emplace(f.id, std::move(f));
    }

    std::vector<Finding> sorted_findings;
    sorted_findings.reserve(deduped.size());
    for (auto& [_, f] : deduped) {
        sorted_findings.push_back(std::move(f));
    }

    std::sort(sorted_findings.begin(), sorted_findings.end(), [](const Finding& a, const Finding& b) {
        if (a.location.file != b.location.file) return a.location.file < b.location.file;
        if (a.location.line != b.location.line) return a.location.line < b.location.line;
        return a.location.col < b.location.col;
    });

    double duration = std::chrono::duration<double>(std::chrono::steady_clock::now() - start_time).count();
    ScanStatistics stats;
    stats.files_scanned = 1;
    stats.parse_errors = 0;
    stats.total_findings = sorted_findings.size();
    stats.duration_seconds = duration;

    for (const auto& f : sorted_findings) {
        stats.findings_by_severity[to_string(f.severity)]++;
    }

    return AnalysisResult(std::move(sorted_findings), stats, std::move(all_errors));
}

} // namespace pyattackmap

