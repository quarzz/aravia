#include "binance.h"
#include "context.h"
#include "logger.h"
#include "price_monitor.h"
#include "trading_bot.h"

#include <iostream>
#include <regex>

namespace {
    std::pair<std::string, std::string> parse_assets(const std::string &symbol) {
        std::regex regex { "([A-Z]+)/([A-Z]+)" };
        std::smatch matches;

        if (std::regex_search(symbol, matches, regex)) {
            return { matches[1], matches[2] };
        } else {
            std::cerr << "symbol format doesn't match AAA/BBB\n";
            exit(-1);
        }
    }
}

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

    const std::string symbol = argv[1];
    std::string base_asset, quote_asset;
    std::tie(base_asset, quote_asset) = parse_assets(symbol);

    Context context;
    context.base_url = "testnet.binance.vision";
    context.api_key = api_key;
    context.secret_key = secret_key;
    context.symbol = base_asset + quote_asset;
    context.base_asset = base_asset;
    context.quote_asset = quote_asset;
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
