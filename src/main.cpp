#include "binance.h"
#include "context.h"
#include "logger.h"
#include "price_monitor.h"
#include "trading_bot.h"

#include <iostream>

int main(int argc, char** argv) {
    if (argc < 7) {
        std::cout << "usage: ./aravia SYMBOL QUANTITY STOP_LOSS STOP_GAIN HOLD_TIMEOUT COOLDOWN_TIME\n";
        return -1;
    }
    const auto api_key = std::getenv("BINANCE_API_KEY");
    if (!api_key) {
        std::cerr << "BINANCE_API_KEY env var is not set\n";
        return -1;
    }
    const auto secret_key = std::getenv("BINANCE_SECRET_KEY");
    if (!secret_key) {
        std::cerr << "BINANCE_SECRET_KEY env var is not set\n";
        return -1;
    }

    Context context;
    context.base_url = "testnet.binance.vision";
    context.api_key = api_key;
    context.secret_key = secret_key;
    context.symbol = argv[1];
    context.quantity = std::stod(argv[2]);
    context.stop_loss = std::stod(argv[3]);
    context.stop_gain = std::stod(argv[4]);
    context.hold_timeout = std::stod(argv[5]);
    context.cooldown_time = std::stoi(argv[6]);

    PriceMonitor price_monitor { context };
    price_monitor.start();

    BinanceApi binance_api { context };
    TradingBot trading_bot { context, binance_api, price_monitor };
    trading_bot.run();

    return 0;
}
