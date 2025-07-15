# Core library
add_library(watr_lib
    protocol.cpp
)

target_include_directories(watr_lib PUBLIC
    ${CMAKE_SOURCE_DIR}/include
)