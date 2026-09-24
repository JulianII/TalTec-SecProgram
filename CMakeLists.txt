cmake_minimum_required(VERSION 3.20)

project(pwm LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(pwm
    src/main.cpp
)