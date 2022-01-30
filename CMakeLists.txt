cmake_minimum_required (VERSION 3.0)

project(crypto_algorithms)

file(GLOB CRYPTO_SOURCES "crypto-algorithms/*.cpp")
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(crypto_algorithms ${CRYPTO_SOURCES})
