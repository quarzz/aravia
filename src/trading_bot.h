#include <chrono>
#include <string>

class BinanceApi;
class Logger;
class PriceMonitor;

class TradingBot {
public:
    enum class State { BUYING, HOLDING, SELLING, SOLD };

    TradingBot(
        BinanceApi &binance_api,
        Logger &logger,
        PriceMonitor &price_monitor,
        double timeout,
        double stop_loss,
        double stop_gain,
        double quantity
    );
    void run();

private:
    void try_buy();
    void check_sell_signals();
    void try_sell();

    void log(const std::string &msg);
    std::string get_new_price_log(const double price) const;

private:
    State m_state = State::BUYING;
    double m_last_price = -100.0;
    double m_buy_price = -100.0;
    std::chrono::time_point<std::chrono::steady_clock> m_bought_at;

    BinanceApi &m_binance_api;
    Logger &m_logger;
    PriceMonitor &m_price_monitor;

    double m_timeout;
    double m_stop_loss;
    double m_stop_gain;
    double m_quantity;
};
