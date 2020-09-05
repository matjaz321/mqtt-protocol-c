cmake_minimum_required(VERSION 3.17)
project(mqtt_protocol_c C)
add_definitions("-D_DEFAULT_SOURCE")
set(CMAKE_C_STANDARD 99)

add_executable(mqtt_protocol_c main.c src/mqtt.h src/mqtt.c)