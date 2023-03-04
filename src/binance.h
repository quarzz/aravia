#ifndef BINANCE_H
#define BINANCE_H

#include <string>

class Context;

class BinanceApi {
public:
    explicit BinanceApi(const Context &context);

    double buy(double quantity);
    double sell(double quantity);

    double get_account_balance();

private:
    const Context &m_context;
};

#endif
