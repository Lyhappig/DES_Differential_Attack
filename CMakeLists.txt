cmake_minimum_required(VERSION 3.24)
project(des_differential_attack)

set(CMAKE_CXX_STANDARD 17)

include_directories(./DES)

add_subdirectory(./Eight_Rounds)
add_subdirectory(./Six_Rounds)
add_subdirectory(./Three_Rounds)

add_executable(des_differential_attack main.cpp ./DES/des.cpp ./DES/des.hpp)

