#include <chrono>

#include "logger.h"
#include "price_monitor.h"

class TradingBot {
public:
    enum class State { BUYING, HOLDING, SELLING, SOLD };

    void run();

private:
    void try_buy();
    void check_sell_signals();
    void try_sell();

private:
    State m_state = State::BUYING;
    double m_last_price = -100.0;
    double m_buy_price = -100.0;
    std::chrono::time_point<std::chrono::steady_clock> m_bought_at;
    Logger m_logger;
    PriceMonitor m_price_monitor;
};
