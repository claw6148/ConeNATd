cmake_minimum_required(VERSION 3.15)
project(ConeNATd)

set(CMAKE_CXX_STANDARD 14)

link_libraries(pthread)
link_libraries(netfilter_queue)

add_executable(ConeNATd main.cpp)