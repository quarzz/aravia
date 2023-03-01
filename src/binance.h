#include <string>

class BinanceApi {
public:
    BinanceApi(
        const std::string &base_url,
        const std::string &api_key,
        const std::string &secret_key,
        const std::string &symbol
    );

    // void getAccountData();
    double buy(double quantity);
    double sell(double quantity);

private:
    std::string m_base_url;
    std::string m_api_key;
    std::string m_secret_key;
    std::string m_symbol;
};
