#include "trading_bot.h"

#include "binance.h"

#include <chrono>

using namespace std::chrono_literals;

static BinanceApi binance_api {
    "testnet.binance.vision",
    "7yMcbL557D7DR37EpVtt04VlNQTAHALxy9fXdiHQSgurS93iBXb0QsK07X9sBvJg",
    "ZoDHcd36vUiUYjRKPyOPXmY0xYhL79MOnym2XXIurf739febp6ePIuSV5COnXN03",
    "BTCUSDT"
};

void TradingBot::run() {
    m_price_monitor.start();
    m_logger.log("price monitor started");

    while (true) {
        const auto now = std::chrono::steady_clock::now();
        const std::chrono::duration<double> ellapsed = now - m_bought_at;

        switch (m_state) {
        case State::BUYING:
            try_buy();
            break;
        case State::HOLDING:

            if (ellapsed.count() >= 30.0) {
                m_logger.log("timeout");
                m_state = State::SELLING;
            } else {
                check_sell_signals();
            }

            break;
        case State::SELLING:
            try_sell();
            break;
        case State::SOLD:
            m_logger.log("sleeping for 15s");
            std::this_thread::sleep_for(15s);
            m_logger.log("back to buying");
            m_state = State::BUYING;
            break;
        }
    }
}

void TradingBot::try_buy() {
    m_logger.log("buying...");
    try {
        m_last_price = m_buy_price = binance_api.buy(0.001);
        m_bought_at = std::chrono::steady_clock::now();
        m_state = State::HOLDING;
        m_logger.log("  bought with price: " + std::to_string(m_buy_price));
    }
    catch(...) {
        m_logger.log("  buy failed, wait one second");
        std::this_thread::sleep_for(1s);
    }
}

void TradingBot::check_sell_signals() {
    const auto cur_price = m_price_monitor.get_price();
    if (cur_price == m_last_price || cur_price < 0)
        return;

    m_logger.log("checking sell signals...");

    m_logger.log("  buy price: " + std::to_string(m_buy_price));
    m_logger.log("  new price: " + std::to_string(cur_price));

    const auto price_delta = cur_price - m_buy_price;
    m_logger.log("  price delta: " + std::to_string(price_delta));
    const auto delta_percent = price_delta / m_buy_price * 100.0;
    m_logger.log("  delta percent: " + std::to_string(delta_percent));

    if (std::abs(delta_percent) >= 0.25) {
        m_state = State::SELLING;
        m_logger.log("  sell signal");
    }

    m_last_price = cur_price;
}

void TradingBot::try_sell() {
    m_logger.log("selling...");
    try {
        const auto sell_price = binance_api.sell(0.001);
        m_state = State::SOLD;
        m_logger.log("  sold with price: " + std::to_string(sell_price));
        const auto profit = 0.001 * (sell_price - m_buy_price);
        m_logger.log("  sold with profit: " + std::to_string(profit));
    }
    catch (...) {
        m_state = State::HOLDING;
        m_logger.log("  sell failed, back to holding");
    }
}
