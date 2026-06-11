#ifndef LOGGER_H
#define LOGGER_H

#include <string>
#include <fstream>
#include <mutex>
#include <chrono>

namespace antiddos {

enum class LogLevel {
    DEBUG = 0,
    INFO = 1,
    WARNING = 2,
    ERROR = 3,
    CRITICAL = 4
};

class Logger {
public:
    static Logger& instance();
    
    void init(const std::string& log_file, LogLevel min_level = LogLevel::INFO);
    void set_console_output(bool enable);
    void set_log_level(LogLevel level);
    
    void debug(const std::string& message);
    void info(const std::string& message);
    void warning(const std::string& message);
    void error(const std::string& message);
    void critical(const std::string& message);
    
    void log(LogLevel level, const std::string& component, const std::string& message);
    
    std::string get_timestamp() const;
    std::string level_to_string(LogLevel level) const;
    
private:
    Logger();
    ~Logger();
    
    void write_log(LogLevel level, const std::string& component, const std::string& message);
    
    std::mutex mutex_;
    std::ofstream log_file_;
    LogLevel min_level_ = LogLevel::INFO;
    bool console_output_ = true;
};

#define LOG_DEBUG(component, msg) antiddos::Logger::instance().log(antiddos::LogLevel::DEBUG, component, msg)
#define LOG_INFO(component, msg) antiddos::Logger::instance().log(antiddos::LogLevel::INFO, component, msg)
#define LOG_WARNING(component, msg) antiddos::Logger::instance().log(antiddos::LogLevel::WARNING, component, msg)
#define LOG_ERROR(component, msg) antiddos::Logger::instance().log(antiddos::LogLevel::ERROR, component, msg)
#define LOG_CRITICAL(component, msg) antiddos::Logger::instance().log(antiddos::LogLevel::CRITICAL, component, msg)

} // namespace antiddos

#endif // LOGGER_H