#include "logger.h"

#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>

namespace {
    std::string get_current_date_time() {
        std::chrono::system_clock::time_point now = std::chrono::system_clock::now();
        std::time_t time = std::chrono::system_clock::to_time_t(now);
        std::stringstream ss;
        ss << std::put_time(std::localtime(&time), "%Y-%m-%d %H:%M:%S");
        return ss.str();
    }
}

void Logger::log(const std::string &str) {
    std::lock_guard<std::mutex> guard(m_mtx);

    std::cout << "[" << get_current_date_time() << "]: " << str << "\n";
}
