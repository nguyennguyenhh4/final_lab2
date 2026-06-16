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
    if(WIN32)
    target_link_libraries(aestool PRIVATE bcrypt)
    endif()

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

# --- GoogleTest / Unit tests ------------------------------------
include(FetchContent)

FetchContent_Declare(
    googletest
    URL https://github.com/google/googletest/archive/refs/tags/v1.15.2.zip
)

# Fix runtime library issue on MSVC/Windows
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)

FetchContent_MakeAvailable(googletest)

enable_testing()

add_executable(aes_tests
    tests/test_aes_core.cpp
)

target_include_directories(aes_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(aes_tests PRIVATE
    GTest::gtest_main
)

if(MSVC)
    target_compile_options(aes_tests PRIVATE /W3 /O2 /std:c++17)
else()
    target_compile_options(aes_tests PRIVATE -Wall -O2 -std=c++17)
endif()

include(GoogleTest)
gtest_discover_tests(aes_tests)

# Also register existing CLI tests into ctest
add_test(
    NAME cli_kat
    COMMAND $<TARGET_FILE:aestool> --kat ${CMAKE_CURRENT_SOURCE_DIR}/nist_vectors.json
)

add_test(
    NAME cli_negative
    COMMAND $<TARGET_FILE:aestool> --test-negative
)

add_test(
    NAME cli_rng_keygen_geniv
    COMMAND ${CMAKE_COMMAND}
        -DAESTOOL=$<TARGET_FILE:aestool>
        -DWORKDIR=${CMAKE_BINARY_DIR}/rng_test
        -P ${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_rng_keygen.cmake
)

message(STATUS "Tests   : aes_tests, cli_kat, cli_negative")

