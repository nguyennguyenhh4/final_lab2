#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

#include "aes128.h"

static uint8_t hex_nibble(char c) {
    if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0');
    if (c >= 'a' && c <= 'f') return static_cast<uint8_t>(c - 'a' + 10);
    if (c >= 'A' && c <= 'F') return static_cast<uint8_t>(c - 'A' + 10);
    throw std::runtime_error("invalid hex");
}

static std::vector<uint8_t> from_hex(const std::string& hex) {
    if (hex.size() % 2 != 0) throw std::runtime_error("odd hex length");

    std::vector<uint8_t> out(hex.size() / 2);
    for (size_t i = 0; i < out.size(); ++i) {
        out[i] = static_cast<uint8_t>(
            (hex_nibble(hex[2 * i]) << 4) | hex_nibble(hex[2 * i + 1])
        );
    }
    return out;
}

TEST(AESCoreTest, FIPS197_AES128_BlockEncrypt) {
    auto key = from_hex("000102030405060708090a0b0c0d0e0f");
    auto pt  = from_hex("00112233445566778899aabbccddeeff");
    auto exp = from_hex("69c4e0d86a7b0430d8cdb78070b4c55a");

    AES aes(key.data(), static_cast<int>(key.size()));

    std::vector<uint8_t> ct(16);
    aes.EncryptBlock(pt.data(), ct.data());

    EXPECT_EQ(ct, exp);
}

TEST(AESCoreTest, FIPS197_AES128_BlockDecrypt) {
    auto key = from_hex("000102030405060708090a0b0c0d0e0f");
    auto ct  = from_hex("69c4e0d86a7b0430d8cdb78070b4c55a");
    auto exp = from_hex("00112233445566778899aabbccddeeff");

    AES aes(key.data(), static_cast<int>(key.size()));

    std::vector<uint8_t> pt(16);
    aes.DecryptBlock(ct.data(), pt.data());

    EXPECT_EQ(pt, exp);
}

TEST(AESCoreTest, RejectInvalidKeyLength) {
    std::array<uint8_t, 15> bad_key{};
    EXPECT_THROW({
        AES aes(bad_key.data(), static_cast<int>(bad_key.size()));
    }, std::invalid_argument);
}

TEST(CTRModeTest, NIST_SP800_38A_AES128_CTR_OneBlock) {
    auto key = from_hex("2b7e151628aed2a6abf7158809cf4f3c");
    auto iv  = from_hex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");

    auto pt = from_hex(
        "6bc1bee22e409f96e93d7e117393172a"
    );

    auto exp = from_hex(
        "874d6191b620e3261bef6864990db6ce"
    );

    AES aes(key.data(), static_cast<int>(key.size()));

    std::vector<uint8_t> ct(pt.size());
    AES_CTR_Process(aes, iv.data(), pt.data(), pt.size(), ct.data());

    EXPECT_EQ(ct, exp);
}

TEST(CTRModeTest, NIST_SP800_38A_AES128_CTR_MultiBlock) {
    auto key = from_hex("2b7e151628aed2a6abf7158809cf4f3c");
    auto iv  = from_hex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");

    auto pt = from_hex(
        "6bc1bee22e409f96e93d7e117393172a"
        "ae2d8a571e03ac9c9eb76fac45af8e51"
        "30c81c46a35ce411e5fbc1191a0a52ef"
        "f69f2445df4f9b17ad2b417be66c3710"
    );

    auto exp = from_hex(
        "874d6191b620e3261bef6864990db6ce"
        "9806f66b7970fdff8617187bb9fffdff"
        "5ae4df3edbd5d35e5b4f09020db03eab"
        "1e031dda2fbe03d1792170a0f3009cee"
    );

    AES aes(key.data(), static_cast<int>(key.size()));

    std::vector<uint8_t> ct(pt.size());
    AES_CTR_Process(aes, iv.data(), pt.data(), pt.size(), ct.data());

    EXPECT_EQ(ct, exp);
}

TEST(CTRModeTest, PartialFinalBlockRoundTrip) {
    auto key = from_hex("2b7e151628aed2a6abf7158809cf4f3c");
    auto iv  = from_hex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");

    std::string msg = "Partial final block test: 31 bytes?";
    std::vector<uint8_t> pt(msg.begin(), msg.end());

    AES aes(key.data(), static_cast<int>(key.size()));

    std::vector<uint8_t> ct(pt.size());
    std::vector<uint8_t> recovered(pt.size());

    AES_CTR_Process(aes, iv.data(), pt.data(), pt.size(), ct.data());
    AES_CTR_Process(aes, iv.data(), ct.data(), ct.size(), recovered.data());

    EXPECT_EQ(recovered, pt);
}

TEST(CTRModeTest, WrongKeyDoesNotRecoverPlaintext) {
    auto key = from_hex("2b7e151628aed2a6abf7158809cf4f3c");
    auto wrong_key = from_hex("000102030405060708090a0b0c0d0e0f");
    auto iv  = from_hex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");

    std::string msg = "wrong key negative test";
    std::vector<uint8_t> pt(msg.begin(), msg.end());

    AES aes(key.data(), static_cast<int>(key.size()));
    AES wrong_aes(wrong_key.data(), static_cast<int>(wrong_key.size()));

    std::vector<uint8_t> ct(pt.size());
    std::vector<uint8_t> recovered(pt.size());

    AES_CTR_Process(aes, iv.data(), pt.data(), pt.size(), ct.data());
    AES_CTR_Process(wrong_aes, iv.data(), ct.data(), ct.size(), recovered.data());

    EXPECT_NE(recovered, pt);
}

TEST(CTRModeTest, TamperedCiphertextCorruptsPlaintext) {
    auto key = from_hex("2b7e151628aed2a6abf7158809cf4f3c");
    auto iv  = from_hex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");

    std::string msg = "tamper test for AES CTR mode";
    std::vector<uint8_t> pt(msg.begin(), msg.end());

    AES aes(key.data(), static_cast<int>(key.size()));

    std::vector<uint8_t> ct(pt.size());
    std::vector<uint8_t> recovered(pt.size());

    AES_CTR_Process(aes, iv.data(), pt.data(), pt.size(), ct.data());

    ct[0] ^= 0x01;

    AES_CTR_Process(aes, iv.data(), ct.data(), ct.size(), recovered.data());

    EXPECT_NE(recovered, pt);
}

TEST(CTRModeTest, CounterOverflowAllowsSingleFinalCounterBlock) {
    auto key = from_hex("000102030405060708090a0b0c0d0e0f");
    auto iv  = from_hex("ffffffffffffffffffffffffffffffff");

    std::vector<uint8_t> pt(16, 0x41);
    std::vector<uint8_t> ct(pt.size());

    AES aes(key.data(), static_cast<int>(key.size()));

    EXPECT_NO_THROW({
        AES_CTR_Process(aes, iv.data(), pt.data(), pt.size(), ct.data());
    });
}

TEST(CTRModeTest, CounterOverflowThrowsWhenMoreBlocksRequired) {
    auto key = from_hex("000102030405060708090a0b0c0d0e0f");
    auto iv  = from_hex("ffffffffffffffffffffffffffffffff");

    // 17 bytes needs 2 CTR blocks.
    // With IV = FF..FF, the second block would wrap to 00..00.
    std::vector<uint8_t> pt(17, 0x41);
    std::vector<uint8_t> ct(pt.size());

    AES aes(key.data(), static_cast<int>(key.size()));

    EXPECT_THROW({
        AES_CTR_Process(aes, iv.data(), pt.data(), pt.size(), ct.data());
    }, std::runtime_error);
}