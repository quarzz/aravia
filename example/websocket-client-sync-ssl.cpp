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
#include <thread>

#include <boost/beast/core.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/websocket/ssl.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <cstdlib>
#include <iostream>
#include <string>

namespace beast = boost::beast;         // from <boost/beast.hpp>
namespace http = beast::http;           // from <boost/beast/http.hpp>
namespace websocket = beast::websocket; // from <boost/beast/websocket.hpp>
namespace net = boost::asio;            // from <boost/asio.hpp>
namespace ssl = boost::asio::ssl;       // from <boost/asio/ssl.hpp>
using tcp = boost::asio::ip::tcp;       // from <boost/asio/ip/tcp.hpp>

// Sends a WebSocket message and prints the response
int main(int argc, char** argv)
{
    try
    {
        // Check command line arguments.
        if(argc != 4)
        {
            std::cerr <<
                "Usage: websocket-client-sync-ssl <host> <port> <text>\n" <<
                "Example:\n" <<
                "    websocket-client-sync-ssl echo.websocket.org 443 \"Hello, world!\"\n";
            return EXIT_FAILURE;
        }
        std::string host = argv[1];
        auto const  port = argv[2];
        auto const  text = argv[3];

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
            std::cout << boost::beast::make_printable(buffer.data()) << "\n";
            std::cout << "FOO\n";
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
