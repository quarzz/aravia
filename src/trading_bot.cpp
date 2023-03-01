#include "trading_bot.h"

#include <chrono>
#include <cstdlib>
#include <future>
#include <iostream>
#include <regex>
#include <string>
#include <thread>

#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/websocket/ssl.hpp>

#include <iostream>
#include <boost/beast.hpp>
#include <boost/asio/ssl.hpp>
#include <openssl/hmac.h>
#include <cstring>

namespace http = boost::beast::http;
namespace asio = boost::asio;
namespace ssl = boost::asio::ssl;

#include <openssl/hmac.h>
#include <sstream>
#include <iomanip>

using namespace std::chrono_literals;

namespace beast = boost::beast;         // from <boost/beast.hpp>
namespace http = beast::http;           // from <boost/beast/http.hpp>
namespace websocket = beast::websocket; // from <boost/beast/websocket.hpp>
namespace net = boost::asio;            // from <boost/asio.hpp>
namespace ssl = boost::asio::ssl;       // from <boost/asio/ssl.hpp>
using tcp = boost::asio::ip::tcp;       // from <boost/asio/ip/tcp.hpp>

namespace {
    // TODO: check if this is standard compliant, cross-platform and UB-friendly
    std::string hmac_sha256(const std::string& key, const std::string& data) {
        unsigned char hmac_digest[EVP_MAX_MD_SIZE];
        unsigned int hmac_digest_len = 0;

        HMAC(EVP_sha256(), key.c_str(), key.length(), (unsigned char*)data.c_str(), data.length(), hmac_digest, &hmac_digest_len);

        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        for (unsigned int i = 0; i < hmac_digest_len; ++i) {
            ss << std::setw(2) << static_cast<unsigned int>(hmac_digest[i]);
        }

        return ss.str();
    }

    void getAccountData() {
        std::string api_key = "7yMcbL557D7DR37EpVtt04VlNQTAHALxy9fXdiHQSgurS93iBXb0QsK07X9sBvJg";
        std::string secret_key = "ZoDHcd36vUiUYjRKPyOPXmY0xYhL79MOnym2XXIurf739febp6ePIuSV5COnXN03";
        std::string endpoint = "/api/v3/account";
        std::string base_url = "testnet.binance.vision";

        asio::io_context ioc;
        ssl::context ctx{ssl::context::tlsv12_client};
        ssl::stream<asio::ip::tcp::socket> stream{ioc, ctx};
        asio::ip::tcp::resolver resolver{ioc};
        auto const results = resolver.resolve(base_url, "443");

        // Set SNI Hostname (many hosts need this to handshake successfully)
        if (!SSL_set_tlsext_host_name(stream.native_handle(), base_url.c_str())) {
            boost::beast::error_code ec{static_cast<int>(::ERR_get_error()), boost::asio::error::get_ssl_category()};
            throw boost::beast::system_error{ec};
        }

        asio::connect(stream.next_layer(), results.begin(), results.end());
        stream.handshake(ssl::stream_base::client);

        // Create request
        http::request<http::empty_body> req{http::verb::get, endpoint, 11};
        req.set(http::field::host, base_url);
        req.set(http::field::user_agent, "Beast");
        req.set("X-MBX-APIKEY", api_key);

        // Add query parameters and signature
        std::string query_string = "timestamp=" + std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count());
        std::string signature = hmac_sha256(secret_key.c_str(), query_string);
        query_string += "&signature=" + signature;
        // std::cout << "URI: " + endpoint + "?" + query_string << std::endl;
        req.target(endpoint + "?" + query_string);

        http::write(stream, req);

        // Read response
        // This buffer is used for reading and must be persisted
        beast::flat_buffer buffer;

        // Declare a container to hold the response
        http::response<http::dynamic_body> res;

        // Receive the HTTP response
        http::read(stream, buffer, res);

        // Write the message to standard out
        std::cout << res << std::endl;

        boost::system::error_code ec;
        stream.shutdown(ec);
        if (ec == boost::asio::error::eof || ec == boost::asio::ssl::error::stream_truncated) {
            ec = {};
        }
        if (ec) {
            throw boost::beast::system_error{ec};
        }
    }

    double buy() {
        std::string api_key = "7yMcbL557D7DR37EpVtt04VlNQTAHALxy9fXdiHQSgurS93iBXb0QsK07X9sBvJg";
        std::string secret_key = "ZoDHcd36vUiUYjRKPyOPXmY0xYhL79MOnym2XXIurf739febp6ePIuSV5COnXN03";
        std::string endpoint = "/api/v3/order";
        std::string base_url = "testnet.binance.vision";

        asio::io_context ioc;
        ssl::context ctx{ssl::context::tlsv12_client};
        ssl::stream<asio::ip::tcp::socket> stream{ioc, ctx};
        asio::ip::tcp::resolver resolver{ioc};
        auto const results = resolver.resolve(base_url, "443");

        // Set SNI Hostname (many hosts need this to handshake successfully)
        if (!SSL_set_tlsext_host_name(stream.native_handle(), base_url.c_str())) {
            boost::beast::error_code ec{static_cast<int>(::ERR_get_error()), boost::asio::error::get_ssl_category()};
            throw boost::beast::system_error{ec};
        }

        asio::connect(stream.next_layer(), results.begin(), results.end());
        stream.handshake(ssl::stream_base::client);

        // Create request
        http::request<http::string_body> req{http::verb::post, endpoint, 11};
        req.set(http::field::host, base_url);
        req.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);
        req.set(http::field::content_type, "application/x-www-form-urlencoded");
        req.set("X-MBX-APIKEY", api_key);

        // Add query parameters and signature
        std::string query_string = "symbol=BTCUSDT&side=BUY&type=MARKET&quantity=0.001";
        query_string += "&timestamp=" + std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count());
        std::string signature = hmac_sha256(secret_key.c_str(), query_string);
        query_string += "&signature=" + signature;
        // std::cout << "QUERY STRING: " << query_string << "\n";
        // std::cout << "Target: " << req.target() << "\n";
        req.target(endpoint + "?" + query_string);
        // req.body() = query_string;

        // std::cout << "BODY: " << req.body() << "\n";

        http::write(stream, req);

        // Read response
        // This buffer is used for reading and must be persisted
        beast::flat_buffer buffer;

        // Declare a container to hold the response
        http::response<http::dynamic_body> res;

        // Receive the HTTP response
        http::read(stream, buffer, res);

        // Write the message to standard out
        std::string body = beast::buffers_to_string(res.body().data());
        // std::cout << "Buy Response Body: " << body << std::endl;
        std::regex re(R"/("fills":.*?"price":"(.*)")/");
        std::smatch match;
        double price = -1;
        if (std::regex_search(body, match, re)) {
            price = std::stod(match[1].str());
            // std::cout << "Buy Price: " << price << std::endl;
        } else {
            // std::cout << "No match found" << std::endl;
        }

        boost::system::error_code ec;
        stream.shutdown(ec);
        if (ec == boost::asio::error::eof || ec == boost::asio::ssl::error::stream_truncated) {
            ec = {};
        }
        if (ec) {
            throw boost::beast::system_error{ec};
        }

        return price;
    }

    double sell() {
        std::string api_key = "7yMcbL557D7DR37EpVtt04VlNQTAHALxy9fXdiHQSgurS93iBXb0QsK07X9sBvJg";
        std::string secret_key = "ZoDHcd36vUiUYjRKPyOPXmY0xYhL79MOnym2XXIurf739febp6ePIuSV5COnXN03";
        std::string endpoint = "/api/v3/order";
        std::string base_url = "testnet.binance.vision";

        asio::io_context ioc;
        ssl::context ctx{ssl::context::tlsv12_client};
        ssl::stream<asio::ip::tcp::socket> stream{ioc, ctx};
        asio::ip::tcp::resolver resolver{ioc};
        auto const results = resolver.resolve(base_url, "443");

        // Set SNI Hostname (many hosts need this to handshake successfully)
        if (!SSL_set_tlsext_host_name(stream.native_handle(), base_url.c_str())) {
            boost::beast::error_code ec{static_cast<int>(::ERR_get_error()), boost::asio::error::get_ssl_category()};
            throw boost::beast::system_error{ec};
        }

        asio::connect(stream.next_layer(), results.begin(), results.end());
        stream.handshake(ssl::stream_base::client);

        // Create request
        http::request<http::string_body> req{http::verb::post, endpoint, 11};
        req.set(http::field::host, base_url);
        req.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);
        req.set(http::field::content_type, "application/x-www-form-urlencoded");
        req.set("X-MBX-APIKEY", api_key);

        // Add query parameters and signature
        std::string query_string = "symbol=BTCUSDT&side=SELL&type=MARKET&quantity=0.001";
        query_string += "&timestamp=" + std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count());
        std::string signature = hmac_sha256(secret_key.c_str(), query_string);
        query_string += "&signature=" + signature;
        // std::cout << "QUERY STRING: " << query_string << "\n";
        // std::cout << "Target: " << req.target() << "\n";
        req.target(endpoint + "?" + query_string);
        // req.body() = query_string;

        // std::cout << "BODY: " << req.body() << "\n";

        http::write(stream, req);

        // Read response
        // This buffer is used for reading and must be persisted
        beast::flat_buffer buffer;

        // Declare a container to hold the response
        http::response<http::dynamic_body> res;

        // Receive the HTTP response
        http::read(stream, buffer, res);

        // Write the message to standard out
        std::string body = beast::buffers_to_string(res.body().data());
        // std::cout << "Sell Response Body: " << body << std::endl;
        std::regex re(R"/("fills":.*?"price":"(.*)")/");
        std::smatch match;
        double price = -1;
        if (std::regex_search(body, match, re)) {
            price = std::stod(match[1].str());
            // std::cout << "Buy Price: " << price << std::endl;
        } else {
            // std::cout << "No match found" << std::endl;
        }

        boost::system::error_code ec;
        stream.shutdown(ec);
        if (ec == boost::asio::error::eof || ec == boost::asio::ssl::error::stream_truncated) {
            ec = {};
        }
        if (ec) {
            throw boost::beast::system_error{ec};
        }

        return price;
    }
}

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
                try_sell();
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
    try {
        m_last_price = m_buy_price = buy();
        m_bought_at = std::chrono::steady_clock::now();
        m_state = State::HOLDING;
        m_logger.log("bought with price: " + std::to_string(m_buy_price));
    }
    catch(...) {
        m_logger.log("buy failed, wait one second");
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
    try {
        const auto sell_price = sell();
        m_state = State::SOLD;
        m_logger.log("sold with price: " + std::to_string(sell_price));
    }
    catch (...) {
        m_state = State::HOLDING;
        m_logger.log("sell failed, back to holding");
    }
}
