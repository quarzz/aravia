#ifndef LOGGER_H
#define LOGGER_H

#include <mutex>

class Logger {
public:
    void log(const std::string &str);

private:
    std::mutex m_mtx;
};

#endif
