#include "price_monitor.h"

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
    // Sends a WebSocket message and prints the response
    int getPricesData(std::atomic<double> &shared_price)
    {
        try
        {
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
            // std::cout << "Look up done.\n";

            // Make the connection on the IP address we get from a lookup
            auto ep = net::connect(beast::get_lowest_layer(ws), results);
            // std::cout << "Connection established\n";

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
            // std::cout << "SSL handshake done\n";


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
            // std::cout << "WebSocket handshake done.\n";

            // std::this_thread::sleep_for(std::chrono::milliseconds { 100 });


            // Send the message
            ws.write(net::buffer(std::string(text)));
            // std::cout << "Message sent [" << text << "]\n";

            for (;;) {
                boost::beast::multi_buffer buffer;
                ws.read(buffer);

                if (buffer.size() == 0) {
                    // std::cout << "Price monitor terminating.\n";
                    break;
                }

                const auto message = boost::beast::buffers_to_string(buffer.data());

                // std::cout << "Price response: " << message << "\n";

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
                    } else {
                        std::cout << "Price not found\n";
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

void PriceMonitor::start() {
    m_future = std::async(std::launch::async, [this]() {
        getPricesData(this->m_price);
    });
}

double PriceMonitor::get_price() {
    return m_price.load();
}
