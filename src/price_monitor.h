#include <atomic>
#include <future>

class Logger;

class PriceMonitor {
public:
    PriceMonitor(Logger &logger, const std::string &symbol);

    void start();
    double get_price();

private:
    std::atomic<double> m_price { -1.0 };
    std::future<void> m_future;

    Logger &m_logger;
    std::string m_symbol;
};
