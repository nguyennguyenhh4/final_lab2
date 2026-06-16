# Cross-validation for Lab 2 AES-128-CTR:
# Compare ciphertext from our aestool with OpenSSL AES-128-CTR.

if(NOT DEFINED AESTOOL)
    message(FATAL_ERROR "AESTOOL is not defined")
endif()

if(NOT DEFINED OPENSSL)
    message(FATAL_ERROR "OPENSSL is not defined")
endif()

if(NOT DEFINED WORKDIR)
    set(WORKDIR "${CMAKE_CURRENT_LIST_DIR}/../build/cross_validation")
endif()

file(MAKE_DIRECTORY "${WORKDIR}")

set(KEY "2b7e151628aed2a6abf7158809cf4f3c")
set(IV  "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")

set(PLAIN "${WORKDIR}/plain.txt")
set(CT_OURS "${WORKDIR}/ct_ours.bin")
set(CT_OPENSSL "${WORKDIR}/ct_openssl.bin")

# Plaintext length is intentionally not a multiple of 16 bytes
# to also test CTR partial-final-block behavior.
file(WRITE "${PLAIN}" "OpenSSL cross-validation for AES-128-CTR partial block test.")

execute_process(
    COMMAND "${AESTOOL}" encrypt --mode ctr
            --key-hex "${KEY}"
            --iv-hex "${IV}"
            --in "${PLAIN}"
            --out "${CT_OURS}"
    RESULT_VARIABLE OUR_RESULT
    OUTPUT_VARIABLE OUR_OUT
    ERROR_VARIABLE OUR_ERR
)

if(NOT OUR_RESULT EQUAL 0)
    message(FATAL_ERROR
        "aestool encryption failed\n"
        "stdout: ${OUR_OUT}\n"
        "stderr: ${OUR_ERR}"
    )
endif()

execute_process(
    COMMAND "${OPENSSL}" enc -aes-128-ctr
            -K "${KEY}"
            -iv "${IV}"
            -nosalt
            -in "${PLAIN}"
            -out "${CT_OPENSSL}"
    RESULT_VARIABLE OPENSSL_RESULT
    OUTPUT_VARIABLE OPENSSL_OUT
    ERROR_VARIABLE OPENSSL_ERR
)

if(NOT OPENSSL_RESULT EQUAL 0)
    message(FATAL_ERROR
        "OpenSSL encryption failed\n"
        "stdout: ${OPENSSL_OUT}\n"
        "stderr: ${OPENSSL_ERR}"
    )
endif()

file(SHA256 "${CT_OURS}" HASH_OURS)
file(SHA256 "${CT_OPENSSL}" HASH_OPENSSL)

message(STATUS "aestool ciphertext SHA256 : ${HASH_OURS}")
message(STATUS "OpenSSL ciphertext SHA256 : ${HASH_OPENSSL}")

if(NOT HASH_OURS STREQUAL HASH_OPENSSL)
    message(FATAL_ERROR
        "FAIL: AES-128-CTR cross-validation mismatch.\n"
        "Our ciphertext    : ${CT_OURS}\n"
        "OpenSSL ciphertext: ${CT_OPENSSL}"
    )
endif()

message(STATUS "PASS: AES-128-CTR ciphertext matches OpenSSL byte-for-byte.")