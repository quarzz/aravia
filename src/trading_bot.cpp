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
{
    m_initial_balance = m_binance_api.get_account_balance();
}

void TradingBot::run() {
    log("started");
    m_is_stopped.store(false);

    while (!m_is_stopped) {
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

    log("stopped");
}

void TradingBot::stop() {
    m_is_stopped.store(true);
}

void TradingBot::try_buy() {
    log("buying...");
    try {
        m_last_price = m_buy_price = m_binance_api.buy(m_context.quantity);
        m_bought_at = std::chrono::steady_clock::now();
        m_state = State::HOLDING;
        std::ostringstream oss;
        oss << "bought: price " << m_buy_price
            << " quantity " << m_context.quantity
            << " spent " << m_buy_price * m_context.quantity;
        log(oss.str());
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

    log("check: " + get_new_price_log(cur_price));

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
        std::ostringstream oss;
        const auto current_balance = m_binance_api.get_account_balance();
        const auto ellapsed_time = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now() - m_started_at
        ).count();
        oss << "balance (" << m_context.quote_asset << "): initial " << m_initial_balance
            << " current " << current_balance
            << " profit " << current_balance - m_initial_balance
            << " [/" << ellapsed_time << "s]";
        log(oss.str());
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
