#ifndef BINANCE_H
#define BINANCE_H

#include <string>

class Context;

class BinanceApi {
public:
    BinanceApi(const Context &context);

    // void getAccountData();
    double buy(double quantity);
    double sell(double quantity);

private:
    const Context &m_context;
};

#endif
