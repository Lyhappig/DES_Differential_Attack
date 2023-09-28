cmake_minimum_required(VERSION 3.24)
project(des_differential_attack)

set(CMAKE_CXX_STANDARD 17)

include_directories(../DES)

SET(EXECUTABLE_OUTPUT_PATH ./bin)

add_executable(eight_attack eight_attack.cpp ../DES/des.cpp)