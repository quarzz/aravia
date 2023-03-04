#ifndef PRICE_MONITOR_H
#define PRICE_MONITOR_H

#include <atomic>
#include <future>

class Context;

class PriceMonitor {
public:
    PriceMonitor(const Context &context);

    void start();
    double get_price();

private:
    void log(const std::string &msg);

private:
    std::atomic<double> m_price { -1.0 };
    std::atomic<bool> m_is_running { false };
    std::future<void> m_future;

    const Context &m_context;
};

#endif
