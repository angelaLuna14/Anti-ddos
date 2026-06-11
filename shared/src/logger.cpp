#include "logger.h"
#include <iostream>
#include <iomanip>
#include <sstream>

namespace antiddos {

Logger::Logger() = default;

Logger::~Logger() {
    if (log_file_.is_open()) {
        log_file_.close();
    }
}

Logger& Logger::instance() {
    static Logger instance;
    return instance;
}

void Logger::init(const std::string& log_file, LogLevel min_level) {
    std::lock_guard<std::mutex> lock(mutex_);
    min_level_ = min_level;
    
    if (!log_file.empty()) {
        log_file_.open(log_file, std::ios::app);
    }
}

void Logger::set_console_output(bool enable) {
    std::lock_guard<std::mutex> lock(mutex_);
    console_output_ = enable;
}

void Logger::set_log_level(LogLevel level) {
    std::lock_guard<std::mutex> lock(mutex_);
    min_level_ = level;
}

void Logger::debug(const std::string& message) {
    log(LogLevel::DEBUG, "SYSTEM", message);
}

void Logger::info(const std::string& message) {
    log(LogLevel::INFO, "SYSTEM", message);
}

void Logger::warning(const std::string& message) {
    log(LogLevel::WARNING, "SYSTEM", message);
}

void Logger::error(const std::string& message) {
    log(LogLevel::ERROR, "SYSTEM", message);
}

void Logger::critical(const std::string& message) {
    log(LogLevel::CRITICAL, "SYSTEM", message);
}

void Logger::log(LogLevel level, const std::string& component, const std::string& message) {
    if (level < min_level_) return;
    write_log(level, component, message);
}

void Logger::write_log(LogLevel level, const std::string& component, const std::string& message) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::string timestamp = get_timestamp();
    std::string level_str = level_to_string(level);
    
    std::ostringstream oss;
    oss << "[" << timestamp << "] "
        << "[" << level_str << "] "
        << "[" << component << "] "
        << message;
    
    std::string log_line = oss.str();
    
    if (console_output_) {
        if (level >= LogLevel::ERROR) {
            std::cerr << log_line << std::endl;
        } else {
            std::cout << log_line << std::endl;
        }
    }
    
    if (log_file_.is_open()) {
        log_file_ << log_line << std::endl;
        log_file_.flush();
    }
}

std::string Logger::get_timestamp() const {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch() % 1000
    ).count();
    
    std::ostringstream oss;
    oss << std::put_time(std::localtime(&time), "%Y-%m-%d %H:%M:%S")
        << "." << std::setfill('0') << std::setw(3) << ms;
    return oss.str();
}

std::string Logger::level_to_string(LogLevel level) const {
    switch (level) {
        case LogLevel::DEBUG:    return "DEBUG";
        case LogLevel::INFO:     return "INFO ";
        case LogLevel::WARNING:  return "WARN ";
        case LogLevel::ERROR:    return "ERROR";
        case LogLevel::CRITICAL: return "CRIT ";
        default:                 return "UNKN ";
    }
}

} // namespace antiddos