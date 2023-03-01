#include <atomic>
#include <future>

class PriceMonitor {
public:
    void start();
    double get_price();

private:
    std::atomic<double> m_price { -1.0 };
    std::future<void> m_future;
};
