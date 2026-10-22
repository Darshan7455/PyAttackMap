#include <chrono>
#include <filesystem>
#include <iostream>
#include <numeric>
#include <vector>

#include "pyattackmap/pyattackmap.hpp"

int main(int argc, char* argv[]) {
    std::filesystem::path corpora_dir = "benchmarks/corpora";
    if (argc > 1) {
        corpora_dir = argv[1];
    }

    std::cout << "============================================================\n"
              << "PyAttackMap Native C++20 In-Process Benchmark\n"
              << "============================================================\n";

    std::vector<std::string> corpora = {"small", "medium", "large"};
    constexpr int TRIALS = 10;

    for (const auto& name : corpora) {
        auto p = corpora_dir / name;
        if (!std::filesystem::exists(p)) {
            continue;
        }

        std::vector<double> times_ms;
        size_t findings = 0;
        size_t files = 0;

        for (int t = 0; t < TRIALS; ++t) {
            auto start = std::chrono::steady_clock::now();
            auto result = pyattackmap::scan(p);
            auto end = std::chrono::steady_clock::now();

            double ms = std::chrono::duration<double, std::milli>(end - start).count();
            times_ms.push_back(ms);
            findings = result.findings().size();
            files = result.statistics().files_scanned;
        }

        double sum = std::accumulate(times_ms.begin(), times_ms.end(), 0.0);
        double avg = sum / times_ms.size();

        std::cout << "Corpus: " << name << " (" << files << " files, " << findings << " findings)\n"
                  << "  Average Duration : " << avg << " ms over " << TRIALS << " trials\n"
                  << "  Throughput       : " << (files / (avg / 1000.0)) << " files/s\n\n";
    }

    return 0;
}

