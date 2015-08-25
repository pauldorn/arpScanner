cmake_minimum_required(VERSION 3.3)
project(arpScanner)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

set(SOURCE_FILES main.cpp listeners.cpp listeners.h arp.cpp arp.h pcap_utils.cpp pcap_utils.h scan_error.cpp scan_error.h)

add_executable(arpScanner ${SOURCE_FILES})
target_link_libraries(arpScanner uv pcap dl)