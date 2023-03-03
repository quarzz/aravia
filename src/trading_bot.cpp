#include "trading_bot.h"

#include "binance.h"
#include "context.h"
#include "logger.h"
#include "price_monitor.h"

#include <chrono>
#include <iomanip>
#include <sstream>
#include <thread>

using namespace std::chrono_literals;

TradingBot::TradingBot(
    const Context &context,
    BinanceApi &binance_api,
    PriceMonitor &price_monitor
) : m_context(context),
    m_binance_api(binance_api),
    m_price_monitor(price_monitor)
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
            if (ellapsed.count() >= m_context.hold_timeout) {
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
            log("wait " + std::to_string(m_context.cooldown_time) + "s before next buy");
            std::this_thread::sleep_for(std::chrono::seconds {m_context.cooldown_time });
            log("back to buying");
            m_state = State::BUYING;
            break;
        }
    }
}

void TradingBot::try_buy() {
    log("buying...");
    try {
        m_last_price = m_buy_price = m_binance_api.buy(m_context.quantity);
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
    const auto profit = price_delta * m_context.quantity;

    log("price: " + get_new_price_log(cur_price));

    if (delta_percent <= -m_context.stop_loss) {
        m_state = State::SELLING;
        log("stop loss");
    } else if (delta_percent >= m_context.stop_gain) {
        m_state = State::SELLING;
        log("stop gain");
    }

    m_last_price = cur_price;
}

void TradingBot::try_sell() {
    log("selling...");
    try {
        const auto sell_price = m_binance_api.sell(m_context.quantity);
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
    m_context.logger.log(prefix);
}

std::string TradingBot::get_new_price_log(const double price) const {
    const auto price_delta = price - m_buy_price;
    const auto delta_percent = price_delta / m_buy_price * 100.0;
    const auto profit = price_delta * m_context.quantity;

    std::ostringstream ss;
    ss.precision(10);
    ss << m_buy_price << "->" << price << " ";
    ss << "(" << price_delta << "/" << std::setprecision(3) << delta_percent << "%";
    ss << " [" << profit << "])";
    return ss.str();
}
