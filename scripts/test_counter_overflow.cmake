if(NOT DEFINED AESTOOL)
    message(FATAL_ERROR "AESTOOL is not defined")
endif()

if(NOT DEFINED WORKDIR)
    set(WORKDIR "${CMAKE_CURRENT_BINARY_DIR}/counter_overflow_test")
endif()

file(MAKE_DIRECTORY "${WORKDIR}")

set(KEY "000102030405060708090a0b0c0d0e0f")
set(MAX_IV "ffffffffffffffffffffffffffffffff")

set(PLAIN16 "${WORKDIR}/plain16.bin")
set(PLAIN17 "${WORKDIR}/plain17.bin")
set(OUT16 "${WORKDIR}/out16.bin")
set(OUT17 "${WORKDIR}/out17.bin")

file(WRITE "${PLAIN16}" "1234567890abcdef")
file(WRITE "${PLAIN17}" "1234567890abcdefX")

# 16 bytes with IV=FF..FF should succeed:
# it uses the final available counter block and does not need another increment.
execute_process(
    COMMAND "${AESTOOL}" encrypt --mode ctr
            --key-hex "${KEY}"
            --iv-hex "${MAX_IV}"
            --in "${PLAIN16}"
            --out "${OUT16}"
    RESULT_VARIABLE R16
    OUTPUT_VARIABLE OUT_OK
    ERROR_VARIABLE ERR_OK
)

if(NOT R16 EQUAL 0)
    message(FATAL_ERROR
        "Expected 16-byte input with max counter to succeed.\n"
        "stdout: ${OUT_OK}\n"
        "stderr: ${ERR_OK}"
    )
endif()

# 17 bytes with IV=FF..FF should fail:
# it needs a second counter block, which would overflow.
execute_process(
    COMMAND "${AESTOOL}" encrypt --mode ctr
            --key-hex "${KEY}"
            --iv-hex "${MAX_IV}"
            --in "${PLAIN17}"
            --out "${OUT17}"
    RESULT_VARIABLE R17
    OUTPUT_VARIABLE OUT_FAIL
    ERROR_VARIABLE ERR_FAIL
)

if(R17 EQUAL 0)
    message(FATAL_ERROR
        "Expected 17-byte input with max counter to fail, but it succeeded."
    )
endif()

message(STATUS "PASS: AES-CTR counter overflow is detected and fails closed.")