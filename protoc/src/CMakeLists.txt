cmake_minimum_required(VERSION 3.10)
project(Custom80211Frame)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find required packages
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBTINS REQUIRED libtins)

# Add executable
add_executable(custom_frame custom.cpp)

# Link libraries
target_link_libraries(custom_frame ${LIBTINS_LIBRARIES})
target_include_directories(custom_frame PRIVATE ${LIBTINS_INCLUDE_DIRS})
target_compile_options(custom_frame PRIVATE ${LIBTINS_CFLAGS_OTHER})

# Set compile flags
target_compile_options(custom_frame PRIVATE -Wall -Wextra)
