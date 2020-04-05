cmake_minimum_required(VERSION 3.15)
project(ConeNATd C)

set(CMAKE_C_STANDARD 99)

link_libraries(pthread)
link_libraries(netfilter_queue)

add_executable(ConeNATd main.c)