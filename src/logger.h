#include <mutex>

class Logger {
public:
    void log(const std::string &str);

private:
    std::mutex m_mtx;
};
