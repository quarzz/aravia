#include "price_monitor.h"

#include "logger.h"

#include <iostream>
#include <regex>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/beast.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/websocket/ssl.hpp>

using tcp = boost::asio::ip::tcp;
namespace net = boost::asio;            // from <boost/asio.hpp>
namespace ssl = boost::asio::ssl;
namespace websocket = boost::beast::websocket;
namespace http = boost::beast::http;
namespace beast = boost::beast;

namespace {
    std::string to_lower(std::string s) {
        std::transform(s.begin(), s.end(), s.begin(), [](char c) {
            return std::tolower(c);
        });
        return s;
    }
    // Sends a WebSocket message and prints the response
    int getPricesData(Logger &logger, const std::string &symbol, std::atomic<double> &shared_price)
    {
        try
        {
            std::string host = "stream.binance.com";
            const std::string port = "443";
            const std::string text = R"({"method":"SUBSCRIBE","params":[")" + to_lower(symbol) + R"(@ticker"],"id":1})";

            // The io_context is required for all I/O
            net::io_context ioc;

            // The SSL context is required, and holds certificates
            ssl::context ctx{ssl::context::tlsv12_client};

            // These objects perform our I/O
            tcp::resolver resolver{ioc};
            websocket::stream<beast::ssl_stream<tcp::socket>> ws{ioc, ctx};

            // Look up the domain name
            auto const results = resolver.resolve(host, port);

            // Make the connection on the IP address we get from a lookup
            auto ep = net::connect(beast::get_lowest_layer(ws), results);

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

            ws.next_layer().handshake(ssl::stream_base::client);


            // Set a decorator to change the User-Agent of the handshake
            ws.set_option(websocket::stream_base::decorator(
                [](websocket::request_type& req) {
                    req.set(http::field::user_agent,
                        std::string(BOOST_BEAST_VERSION_STRING) +
                            " websocket-client-coro");
                    req.set(http::field::content_type, "application/json");
                })
            );

            ws.handshake(host, "/ws");
            ws.write(net::buffer(std::string(text)));

            for (;;) {
                boost::beast::multi_buffer buffer;
                ws.read(buffer);

                if (buffer.size() == 0) {
                    break;
                }

                const auto message = boost::beast::buffers_to_string(buffer.data());

                if (message == "ping") {
                    buffer.consume(buffer.size());
                    ws.write(boost::asio::buffer("pong"));
                } else {
                    std::regex bid_price_regex("\"b\":\"(.*?)\"");
                    std::regex ask_price_regex("\"a\":\"(.*?)\"");
                    double bid_price = -1.0;
                    double ask_price = -1.0;

                    std::smatch bid_match;
                    if (std::regex_search(message, bid_match, bid_price_regex)) {
                        bid_price = std::stod(bid_match[1].str());
                    }

                    std::smatch ask_match;
                    if (std::regex_search(message, ask_match, ask_price_regex)) {
                        ask_price = std::stod(ask_match[1].str());
                    }

                    if (bid_price >= 0 && ask_price >= 0) {
                        const auto mid_price = (bid_price + ask_price) / 2;
                        shared_price.store(mid_price);
                        std::ostringstream ss;
                        ss.precision(15);
                        ss << "[price_monitor] fetch: bid " << bid_price
                            << " ask " << ask_price << " mid " << mid_price;
                        logger.log(ss.str());
                    } else {
                        logger.log("[price_monitor] price not found");
                    }
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
}

PriceMonitor::PriceMonitor(Logger &logger, const std::string &symbol)
: m_logger(logger), m_symbol(symbol)
{}

void PriceMonitor::start() {
    m_future = std::async(std::launch::async, [this]() {
        getPricesData(m_logger, m_symbol, this->m_price);
    });
}

double PriceMonitor::get_price() {
    return m_price.load();
}
