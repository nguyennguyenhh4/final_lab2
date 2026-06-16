if(NOT DEFINED AESTOOL)
    message(FATAL_ERROR "AESTOOL is not defined")
endif()

if(NOT DEFINED WORKDIR)
    set(WORKDIR "${CMAKE_CURRENT_BINARY_DIR}/rng_test")
endif()

file(MAKE_DIRECTORY "${WORKDIR}")

set(KEY1 "${WORKDIR}/key1.bin")
set(KEY2 "${WORKDIR}/key2.bin")
set(IV1  "${WORKDIR}/iv1.bin")
set(IV2  "${WORKDIR}/iv2.bin")

execute_process(
    COMMAND "${AESTOOL}" keygen --bits 128 --out "${KEY1}"
    RESULT_VARIABLE R1
)
if(NOT R1 EQUAL 0)
    message(FATAL_ERROR "keygen key1 failed")
endif()

execute_process(
    COMMAND "${AESTOOL}" keygen --bits 128 --out "${KEY2}"
    RESULT_VARIABLE R2
)
if(NOT R2 EQUAL 0)
    message(FATAL_ERROR "keygen key2 failed")
endif()

execute_process(
    COMMAND "${AESTOOL}" geniv --out "${IV1}"
    RESULT_VARIABLE R3
)
if(NOT R3 EQUAL 0)
    message(FATAL_ERROR "geniv iv1 failed")
endif()

execute_process(
    COMMAND "${AESTOOL}" geniv --out "${IV2}"
    RESULT_VARIABLE R4
)
if(NOT R4 EQUAL 0)
    message(FATAL_ERROR "geniv iv2 failed")
endif()

file(SIZE "${KEY1}" KEY1_SIZE)
file(SIZE "${KEY2}" KEY2_SIZE)
file(SIZE "${IV1}" IV1_SIZE)
file(SIZE "${IV2}" IV2_SIZE)

if(NOT KEY1_SIZE EQUAL 16)
    message(FATAL_ERROR "key1 size must be 16 bytes")
endif()

if(NOT KEY2_SIZE EQUAL 16)
    message(FATAL_ERROR "key2 size must be 16 bytes")
endif()

if(NOT IV1_SIZE EQUAL 16)
    message(FATAL_ERROR "iv1 size must be 16 bytes")
endif()

if(NOT IV2_SIZE EQUAL 16)
    message(FATAL_ERROR "iv2 size must be 16 bytes")
endif()

file(SHA256 "${KEY1}" KEY1_HASH)
file(SHA256 "${KEY2}" KEY2_HASH)
file(SHA256 "${IV1}" IV1_HASH)
file(SHA256 "${IV2}" IV2_HASH)

if(KEY1_HASH STREQUAL KEY2_HASH)
    message(FATAL_ERROR "two generated keys are identical")
endif()

if(IV1_HASH STREQUAL IV2_HASH)
    message(FATAL_ERROR "two generated IVs are identical")
endif()

message(STATUS "PASS: OS CSPRNG keygen/geniv generated valid non-identical 16-byte outputs.")