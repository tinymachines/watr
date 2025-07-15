cmake_minimum_required(VERSION 3.18)
project(watr VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Platform detection
if(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64|ARM64")
    set(IS_ARM64 TRUE)
    message(STATUS "Building for ARM64 architecture")
    
    # ARM64 optimizations for Raspberry Pi 4
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -march=armv8-a+crc+crypto")
    endif()
endif()

# Find Python
find_package(Python3 COMPONENTS Interpreter Development REQUIRED)

# Find pybind11
find_package(pybind11 REQUIRED)

# Add subdirectories
add_subdirectory(src)

# Create Python bindings
pybind11_add_module(watr_core src/bindings.cpp)
target_link_libraries(watr_core PRIVATE watr_lib)
target_compile_definitions(watr_core PRIVATE VERSION_INFO=${VERSION_INFO})

# Install targets for distribution
install(TARGETS watr_core DESTINATION ${Python3_SITELIB}/watr)
install(DIRECTORY python/watr/ DESTINATION ${Python3_SITELIB}/watr
        FILES_MATCHING PATTERN "*.py")