#ifndef CONTEXT_H
#define CONTEXT_H

#include <string>

#include "logger.h"

struct Context {
    std::string base_url;
    std::string api_key;
    std::string secret_key;
    std::string symbol;
    std::string base_asset;
    std::string quote_asset;
    double quantity;
    double stop_loss;
    double stop_gain;
    double hold_timeout;
    int cooldown_time;
    mutable Logger logger;
};

#endif
