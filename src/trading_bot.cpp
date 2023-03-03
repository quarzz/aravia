#include "trading_bot.h"

#include "binance.h"
#include "logger.h"
#include "price_monitor.h"

#include <chrono>
#include <iomanip>
#include <sstream>

using namespace std::chrono_literals;

TradingBot::TradingBot(
    BinanceApi &binance_api,
    Logger &logger,
    PriceMonitor &price_monitor,
    double timeout,
    double stop_loss,
    double stop_gain,
    double quantity
) : m_binance_api(binance_api),
    m_logger(logger),
    m_price_monitor(price_monitor),
    m_timeout(timeout),
    m_stop_loss(stop_loss),
    m_stop_gain(stop_gain),
    m_quantity(quantity)
{}

void TradingBot::run() {
    while (true) {
        const auto now = std::chrono::steady_clock::now();
        const std::chrono::duration<double> ellapsed = now - m_bought_at;

        switch (m_state) {
        case State::BUYING:
            try_buy();
            break;
        case State::HOLDING:
            if (ellapsed.count() >= m_timeout) {
                log("timeout");
                m_state = State::SELLING;
            } else {
                check_sell_signals();
            }

            break;
        case State::SELLING:
            try_sell();
            break;
        case State::SOLD:
            log("sleeping for 15s");
            std::this_thread::sleep_for(15s);
            log("back to buying");
            m_state = State::BUYING;
            break;
        }
    }
}

void TradingBot::try_buy() {
    log("buying...");
    try {
        m_last_price = m_buy_price = m_binance_api.buy(m_quantity);
        m_bought_at = std::chrono::steady_clock::now();
        m_state = State::HOLDING;
        log("bought: " + std::to_string(m_buy_price));
    }
    catch(...) {
        log("buying failed, wait one second");
        std::this_thread::sleep_for(1s);
    }
}

void TradingBot::check_sell_signals() {
    const auto cur_price = m_price_monitor.get_price();
    if (cur_price == m_last_price || cur_price < 0)
        return;

    const auto price_delta = cur_price - m_buy_price;
    const auto delta_percent = price_delta / m_buy_price * 100.0;
    const auto profit = price_delta * m_quantity;

    log("price: " + get_new_price_log(cur_price));

    if (delta_percent <= -m_stop_loss) {
        m_state = State::SELLING;
        log("stop loss");
    } else if (delta_percent >= m_stop_gain) {
        m_state = State::SELLING;
        log("stop gain");
    }

    m_last_price = cur_price;
}

void TradingBot::try_sell() {
    log("selling...");
    try {
        const auto sell_price = m_binance_api.sell(m_quantity);
        m_state = State::SOLD;
        log("sold: " + get_new_price_log(sell_price));
    }
    catch (...) {
        m_state = State::HOLDING;
        log("selling failed, back to holding");
    }
}

void TradingBot::log(const std::string &msg) {
    std::string prefix = "[trading_bot] ";
    prefix += msg;
    m_logger.log(prefix);
}

std::string TradingBot::get_new_price_log(const double price) const {
    const auto price_delta = price - m_buy_price;
    const auto delta_percent = price_delta / m_buy_price * 100.0;
    const auto profit = price_delta * m_quantity;

    std::ostringstream ss;
    ss.precision(10);
    ss << m_buy_price << "->" << price << " ";
    ss << "(" << price_delta << "/" << std::setprecision(3) << delta_percent << "%";
    ss << " [" << profit << "])";
    return ss.str();
}
