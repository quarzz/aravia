cmake_minimum_required(VERSION 3.5)
project(aravia)

set(CMAKE_CXX_STANDARD 14)

# Find OpenSSL
find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})
link_libraries(${OPENSSL_LIBRARIES})

# Find Boost Beast
find_package(Boost REQUIRED)
include_directories(${Boost_INCLUDE_DIRS})
link_libraries(${Boost_LIBRARIES})

# Add executable target
add_executable(aravia
    src/logger.cpp
    src/price_monitor.cpp
    src/trading_bot.cpp
    src/main.cpp
)
