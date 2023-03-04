#ifndef TRADING_BOT_H
#define TRADING_BOT_H

#include <chrono>
#include <string>

class BinanceApi;
class Context;
class PriceMonitor;

class TradingBot {
public:
    enum class State { BUYING, HOLDING, SELLING, SOLD };

    TradingBot(
        const Context &context,
        BinanceApi &binance_api,
        PriceMonitor &price_monitor
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

    const Context &m_context;
    BinanceApi &m_binance_api;
    PriceMonitor &m_price_monitor;

    double m_initial_balance;
    std::chrono::time_point<std::chrono::steady_clock> m_started_at = std::chrono::steady_clock::now();
};

#endif
