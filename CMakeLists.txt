cmake_minimum_required(VERSION 3.16)
project(AES_Lab2 CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# --- NO external crypto library — pure C++ ---------------------
# (Constraint: no OpenSSL, Crypto++, libsodium, etc.)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

# --- aestool ---------------------------------------------------
add_executable(aestool aestool.cpp)
target_include_directories(aestool PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

if(MSVC)
  target_compile_options(aestool PRIVATE /W3 /O2 /std:c++17)
else()
  target_compile_options(aestool PRIVATE -Wall -O2 -std=c++17)
endif()

# --- bench ----------------------------------------------------
add_executable(bench bench.cpp)
target_include_directories(bench PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

if(MSVC)
  target_compile_options(bench PRIVATE /W3 /O3 /std:c++17)
else()
  # -O3 -march=native for best performance comparison vs Crypto++
  target_compile_options(bench PRIVATE -Wall -O3 -march=native -std=c++17)
endif()

# --- Install ---------------------------------------------------
install(TARGETS aestool bench DESTINATION bin)

message(STATUS "Build type  : ${CMAKE_BUILD_TYPE}")
message(STATUS "C++ standard: C++${CMAKE_CXX_STANDARD}")
message(STATUS "Targets     : aestool, bench")
message(STATUS "Constraint  : No external crypto library")
