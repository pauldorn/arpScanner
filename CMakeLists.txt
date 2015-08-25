cmake_minimum_required(VERSION 2.8)
project(arpScanner)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

set(SOURCE_FILES main.cpp)

add_executable(arpScanner ${SOURCE_FILES})
target_link_libraries(arpScanner uv pcap dl)