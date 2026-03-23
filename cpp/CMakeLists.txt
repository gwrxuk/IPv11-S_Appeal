cmake_minimum_required(VERSION 3.16)
project(ipv11s_openclaw_cpp LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(ipv11s_openclaw src/ipv11s_openclaw.cpp)
