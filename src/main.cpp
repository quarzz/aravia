#include "binance.h"
#include "logger.h"
#include "price_monitor.h"
#include "trading_bot.h"

#include <iostream>

int main(int argc, char** argv) {
    if (argc < 3) {
        std::cout << "usage: ./aravia SYMBOL QUANTITY\n";
        return -1;
    }

    const std::string api_key = "7yMcbL557D7DR37EpVtt04VlNQTAHALxy9fXdiHQSgurS93iBXb0QsK07X9sBvJg";
    const std::string secret_key = "ZoDHcd36vUiUYjRKPyOPXmY0xYhL79MOnym2XXIurf739febp6ePIuSV5COnXN03";
    const std::string symbol = argv[1];
    const auto quantity = std::stod(argv[2]);

    Logger logger;
    PriceMonitor price_monitor(logger, symbol);
    price_monitor.start();

    BinanceApi binance_api { "testnet.binance.vision", api_key, secret_key, symbol };
    TradingBot trading_bot(binance_api, logger, price_monitor, 30.0, 0.02, 0.02, quantity);
    trading_bot.run();

    return 0;
}
