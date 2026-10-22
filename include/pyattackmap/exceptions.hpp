#pragma once

#include <stdexcept>
#include <string>

namespace pyattackmap {

class PyAttackMapException : public std::runtime_error {
public:
    explicit PyAttackMapException(const std::string& message) : std::runtime_error(message) {}
};

class ConfigException : public PyAttackMapException {
public:
    explicit ConfigException(const std::string& message) : PyAttackMapException(message) {}
};

class ParseException : public PyAttackMapException {
public:
    explicit ParseException(const std::string& file_path, const std::string& message, size_t line = 0)
        : PyAttackMapException("Parse error in '" + file_path + "' at line " + std::to_string(line) + ": " + message),
          file_path_(file_path),
          line_(line) {}

    [[nodiscard]] const std::string& file_path() const noexcept { return file_path_; }
    [[nodiscard]] size_t line() const noexcept { return line_; }

private:
    std::string file_path_;
    size_t line_;
};

class FileAccessException : public PyAttackMapException {
public:
    explicit FileAccessException(const std::string& message) : PyAttackMapException(message) {}
};

class RuleException : public PyAttackMapException {
public:
    explicit RuleException(const std::string& message) : PyAttackMapException(message) {}
};

class ScanError : public PyAttackMapException {
public:
    explicit ScanError(const std::string& message) : PyAttackMapException(message) {}
};

} // namespace pyattackmap

