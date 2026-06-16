cmake_minimum_required(VERSION 3.22.1)
project("securitysample")

add_library(
    securitysample
    SHARED
    security_checks.c
)

target_link_libraries(
    securitysample
    log
    dl
)
