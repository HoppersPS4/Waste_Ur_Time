cmake_minimum_required(VERSION 4.0)
project(waster_ur_time)
add_executable(${PROJECT_NAME})

# Set the C++ standard to use
set(CMAKE_CXX_STANDARD 26)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Generate compile_commands.json
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Configure system to allow us to fetch remote stuff
include(FetchContent)
set(FETCHCONTENT_QUIET TRUE)
SET(BUILD_EXAMPLES OFF CACHE BOOL "" FORCE) # Don't build examples

# Import RocksDB
target_link_libraries(${PROJECT_NAME} PRIVATE rocksdb)

# Set default build type
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Debug)
endif()

# Enable warnings
if (CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
  add_compile_options(-Wall -Wextra -Wpedantic)
elseif (MSVC)
  add_compile_options(/W4)
endif()

# Add source codes
file(GLOB_RECURSE PROJECT_SOURCES CONFIGURE_DEPENDS "${CMAKE_CURRENT_LIST_DIR}/PS4_Passcode_Bruteforcer/*.cpp")
set(PROJECT_INCLUDE "${CMAKE_CURRENT_LIST_DIR}/PS4_Passcode_Bruteforcer/")

# Declare the final executable
target_sources(${PROJECT_NAME} PRIVATE ${PROJECT_SOURCES})
target_include_directories(${PROJECT_NAME} PRIVATE ${PROJECT_INCLUDE})
