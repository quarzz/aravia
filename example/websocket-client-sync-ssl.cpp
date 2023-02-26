//
// Copyright (c) 2016-2019 Vinnie Falco (vinnie dot falco at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/boostorg/beast
//

//------------------------------------------------------------------------------
//
// Example: WebSocket SSL client, synchronous
//
//------------------------------------------------------------------------------
#include <chrono>
#include <cstdlib>
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

namespace beast = boost::beast;         // from <boost/beast.hpp>
namespace http = beast::http;           // from <boost/beast/http.hpp>
namespace websocket = beast::websocket; // from <boost/beast/websocket.hpp>
namespace net = boost::asio;            // from <boost/asio.hpp>
namespace ssl = boost::asio::ssl;       // from <boost/asio/ssl.hpp>
using tcp = boost::asio::ip::tcp;       // from <boost/asio/ip/tcp.hpp>

// Sends a WebSocket message and prints the response
int getPricesData(/*int argc, char** argv*/)
{
    try
    {
        // // Check command line arguments.
        // if(argc != 4)
        // {
        //     std::cerr <<
        //         "Usage: websocket-client-sync-ssl <host> <port> <text>\n" <<
        //         "Example:\n" <<
        //         "    websocket-client-sync-ssl echo.websocket.org 443 \"Hello, world!\"\n";
        //     return EXIT_FAILURE;
        // }
        // std::string host = argv[1];
        std::string host { "stream.binance.com" };
        std::string port { "443" };
        std::string text { R"({"method":"SUBSCRIBE","params":["btcusdt@ticker"],"id":1})" };

        // The io_context is required for all I/O
        net::io_context ioc;

        // The SSL context is required, and holds certificates
        ssl::context ctx{ssl::context::tlsv12_client};

        // These objects perform our I/O
        tcp::resolver resolver{ioc};
        websocket::stream<beast::ssl_stream<tcp::socket>> ws{ioc, ctx};

        // Look up the domain name
        auto const results = resolver.resolve(host, port);
        std::cout << "Look up done.\n";

        // Make the connection on the IP address we get from a lookup
        auto ep = net::connect(get_lowest_layer(ws), results);
        std::cout << "Connection established\n";

        // Set SNI Hostname (many hosts need this to handshake successfully)
        if(! SSL_set_tlsext_host_name(ws.next_layer().native_handle(), host.c_str()))
            throw beast::system_error(
                beast::error_code(
                    static_cast<int>(::ERR_get_error()),
                    net::error::get_ssl_category()),
                "Failed to set SNI Hostname");

        // Update the host_ string. This will provide the value of the
        // Host HTTP header during the WebSocket handshake.
        // See https://tools.ietf.org/html/rfc7230#section-5.4
        host += ':' + std::to_string(ep.port());

        // Perform the SSL handshake
        ws.next_layer().handshake(ssl::stream_base::client);
        std::cout << "SSL handshake done\n";


        // Set a decorator to change the User-Agent of the handshake
        ws.set_option(websocket::stream_base::decorator(
            [](websocket::request_type& req)
            {
                req.set(http::field::user_agent,
                    std::string(BOOST_BEAST_VERSION_STRING) +
                        " websocket-client-coro");
                req.set(http::field::content_type, "application/json");
            }));

        // Perform the websocket handshake
        ws.handshake(host, "/ws");
        std::cout << "WebSocket handshake done.\n";

        std::this_thread::sleep_for(std::chrono::milliseconds { 100 });


        // Send the message
        ws.write(net::buffer(std::string(text)));
        std::cout << "Message sent [" << text << "]\n";

        for (;;) {
            boost::beast::multi_buffer buffer;
            ws.read(buffer);
            std::string resp { beast::buffers_to_string(buffer.data()) };
            std::regex re("\"w\":\"(\\d+\\.\\d+)\"");
            std::smatch match;
            if (std::regex_search(resp, match, re)) {
                double price = std::stod(match[1].str());
                std::cout << "Price: " << price << std::endl;
            } else {
                std::cout << "No match found" << std::endl;
                std::cout << resp << "\n";
            }
            // std::cout << beast::make_printable(buffer.data()) << "\n";
            if (buffer.size() == 0) {
                break;
            }
            auto message = boost::beast::buffers_to_string(buffer.data());
            if (message == "ping") {
                buffer.consume(buffer.size());
                ws.write(boost::asio::buffer("pong"));
            }
        }
    }
    catch(std::exception const& e)
    {
        std::cerr << "Error: " << e.what() << std::endl;
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

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
    std::cout << "URI: " + endpoint + "?" + query_string << std::endl;
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

void buy() {
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
    std::cout << "QUERY STRING: " << query_string << "\n";
    std::cout << "Target: " << req.target() << "\n";
    req.target(endpoint + "?" + query_string);
    // req.body() = query_string;

    std::cout << "BODY: " << req.body() << "\n";

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

int main(int argc, char** argv) {
    std::cout << "Account data BEFORE trade:\n";
    getAccountData();

    buy();

    std::cout << "Account data AFTER trade:\n";
    getAccountData();
}
