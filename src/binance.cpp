#include "binance.h"

#include "context.h"

#include <openssl/hmac.h>
#include <sstream>
#include <iomanip>
#include <iostream>
#include <regex>

#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/websocket/ssl.hpp>

namespace http = boost::beast::http;
namespace asio = boost::asio;
namespace ssl = boost::asio::ssl;
namespace beast = boost::beast;         // from <boost/beast.hpp>
namespace http = beast::http;           // from <boost/beast/http.hpp>
namespace websocket = beast::websocket; // from <boost/beast/websocket.hpp>
namespace net = boost::asio;            // from <boost/asio.hpp>
namespace ssl = boost::asio::ssl;       // from <boost/asio/ssl.hpp>
using tcp = boost::asio::ip::tcp;       // from <boost/asio/ip/tcp.hpp>

using namespace std::chrono_literals;

namespace {
    // TODO: check if this is standard compliant, cross-platform and UB-friendly
    std::string hmac_sha256(const std::string& key, const std::string& data) {
        unsigned char hmac_digest[EVP_MAX_MD_SIZE];
        unsigned int hmac_digest_len = 0;

        HMAC(
            EVP_sha256(),
            key.c_str(),
            key.length(),
            reinterpret_cast<const unsigned char*>(data.c_str()),
            data.length(),
            hmac_digest,
            &hmac_digest_len
        );

        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        for (unsigned int i = 0; i < hmac_digest_len; ++i) {
            ss << std::setw(2) << static_cast<unsigned int>(hmac_digest[i]);
        }

        return ss.str();
    }

    void query_binance(
        const std::string &base_url,
        const http::verb http_verb,
        const std::string &api_key,
        const std::string &secret_key,
        const std::string &endpoint,
        std::string query_string,
        beast::flat_buffer &buffer,
        http::response<http::dynamic_body> &resp
    ) {
        asio::io_context ioc;
        ssl::context ctx { ssl::context::tlsv12_client };
        ssl::stream<asio::ip::tcp::socket> stream { ioc, ctx };
        asio::ip::tcp::resolver resolver { ioc };
        auto const results = resolver.resolve(base_url, "443");

        // Set SNI Hostname (many hosts need this to handshake successfully)
        if (!SSL_set_tlsext_host_name(stream.native_handle(), base_url.c_str())) {
            boost::beast::error_code ec {
                static_cast<int>(::ERR_get_error()),
                boost::asio::error::get_ssl_category()
            };
            throw boost::beast::system_error{ec};
        }

        asio::connect(stream.next_layer(), results.begin(), results.end());
        stream.handshake(ssl::stream_base::client);

        http::request<http::empty_body> req { http_verb, endpoint, 11 };
        req.set(http::field::host, base_url);
        req.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);
        req.set("X-MBX-APIKEY", api_key);

        if (query_string.empty())
            query_string = "timestamp=" + std::to_string(
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::system_clock::now().time_since_epoch()
                ).count()
            );
        else
            query_string += "&timestamp=" + std::to_string(
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::system_clock::now().time_since_epoch()
                ).count()
            );
        std::string signature = hmac_sha256(secret_key, query_string);
        req.target(endpoint + "?" + query_string + "&signature=" + signature);

        http::write(stream, req);
        http::read(stream, buffer, resp);

        if (resp.result_int() != 200)
            throw std::runtime_error { "binance respont with code != 200" };

        boost::system::error_code ec;
        stream.shutdown(ec);
        if (ec == boost::asio::error::eof || ec == boost::asio::ssl::error::stream_truncated) {
            ec = {};
        }
        if (ec) {
            throw boost::beast::system_error{ec};
        }
    }

    double parse_price_from_order(const http::response<http::dynamic_body> &resp) {
        std::string body = beast::buffers_to_string(resp.body().data());
        std::regex price_regex(R"/("fills":.*?"price":"(.*?)")/");
        std::smatch match;

        if (std::regex_search(body, match, price_regex)) {
            const auto price = std::stod(match[1].str());
            if (price >= 0)
                return price;
        }

        throw std::runtime_error { "price not found in order response" };
    }

    double parse_balance_from_account(
        const http::response<http::dynamic_body> &resp,
        const std::string &asset
    ) {
        const std::string body = beast::buffers_to_string(resp.body().data());
        std::regex regex { "\"asset\":\"" + asset + "\".*?\"free\":.*?\"(.*?)\"" };
        std::smatch matches;

        if (std::regex_search(body, matches, regex)) {
            return std::stod(matches[1]);
        } else {
            throw std::runtime_error { "balance not found in account response" };
        }
    }
}

BinanceApi::BinanceApi(const Context &context): m_context(context)
{}

double BinanceApi::buy(double quantity) {
    beast::flat_buffer buffer;
    http::response<http::dynamic_body> resp;

    const std::string endpoint = "/api/v3/order";
    const std::string query_string =
        "symbol=" + m_context.symbol + "&side=BUY&type=MARKET&quantity=" + std::to_string(quantity);

    query_binance(m_context.base_url, http::verb::post, m_context.api_key, m_context.secret_key, endpoint, query_string, buffer, resp);

    return parse_price_from_order(resp);
}

double BinanceApi::sell(double quantity) {
    beast::flat_buffer buffer;
    http::response<http::dynamic_body> resp;

    const std::string endpoint = "/api/v3/order";
    const std::string query_string =
        "symbol=" + m_context.symbol + "&side=SELL&type=MARKET&quantity=" + std::to_string(quantity);

    query_binance(m_context.base_url, http::verb::post, m_context.api_key, m_context.secret_key, endpoint, query_string, buffer, resp);

    return parse_price_from_order(resp);
}

double BinanceApi::get_account_balance() {
    beast::flat_buffer buffer;
    http::response<http::dynamic_body> resp;

    const std::string endpoint = "/api/v3/account";
    const std::string query_string;

    query_binance(m_context.base_url, http::verb::get, m_context.api_key, m_context.secret_key, endpoint, query_string, buffer, resp);
    return parse_balance_from_account(resp, m_context.quote_asset);
}
