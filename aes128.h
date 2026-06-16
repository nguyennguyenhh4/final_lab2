#pragma once
/**
 * aes128.h — Pure C++ AES Implementation (FIPS-197 Compliant)
 *
 * Supports : AES-128, AES-192, AES-256
 * No external crypto libraries used.
 * STL only.
 *
 * FIPS-197 reference: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf
 */

#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
#include <array>
#include <vector>

// ----------------------------------------------------------------
//  AES constants
// ----------------------------------------------------------------
static constexpr int AES_BLOCK_SIZE = 16; // bytes

// AES S-box (FIPS-197, Figure 7)
static constexpr uint8_t SBOX[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

// AES inverse S-box (FIPS-197, Figure 14)
static constexpr uint8_t INV_SBOX[256] = {
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
};

// Round constants (FIPS-197, Section 5.2)
static constexpr uint8_t RCON[11] = {
    0x00, // unused (index 0)
    0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36
};

// ----------------------------------------------------------------
//  GF(2^8) multiplication — xtime (multiply by 2 in GF(2^8))
// ----------------------------------------------------------------
static inline uint8_t xtime(uint8_t a)
{
    return (uint8_t)((a << 1) ^ ((a >> 7) ? 0x1b : 0x00));
}

// GF(2^8) multiply — used in MixColumns
static inline uint8_t gf_mul(uint8_t a, uint8_t b)
{
    uint8_t result = 0;
    for (int i = 0; i < 8; ++i) {
        if (b & 1) result ^= a;
        uint8_t hi = a >> 7;
        a <<= 1;
        if (hi) a ^= 0x1b;
        b >>= 1;
    }
    return result;
}

// ----------------------------------------------------------------
//  AES State  (4×4 bytes, column-major per FIPS-197)
// ----------------------------------------------------------------
using AESBlock  = std::array<uint8_t, 16>;
using AESState  = uint8_t[4][4]; // state[row][col]

static inline void BlockToState(const uint8_t* block, AESState s)
{
    for (int r = 0; r < 4; ++r)
        for (int c = 0; c < 4; ++c)
            s[r][c] = block[r + 4 * c];
}

static inline void StateToBlock(const AESState s, uint8_t* block)
{
    for (int r = 0; r < 4; ++r)
        for (int c = 0; c < 4; ++c)
            block[r + 4 * c] = s[r][c];
}

// ----------------------------------------------------------------
//  Round transformations (FIPS-197, Section 5.1)
// ----------------------------------------------------------------

// AddRoundKey (FIPS-197, Section 5.1.4)
static inline void AddRoundKey(AESState s, const uint32_t* rk, int round)
{
    for (int c = 0; c < 4; ++c) {
        uint32_t w = rk[round * 4 + c];
        s[0][c] ^= (uint8_t)(w >> 24);
        s[1][c] ^= (uint8_t)(w >> 16);
        s[2][c] ^= (uint8_t)(w >>  8);
        s[3][c] ^= (uint8_t)(w);
    }
}

// SubBytes (FIPS-197, Section 5.1.1)
static inline void SubBytes(AESState s)
{
    for (int r = 0; r < 4; ++r)
        for (int c = 0; c < 4; ++c)
            s[r][c] = SBOX[s[r][c]];
}

// InvSubBytes
static inline void InvSubBytes(AESState s)
{
    for (int r = 0; r < 4; ++r)
        for (int c = 0; c < 4; ++c)
            s[r][c] = INV_SBOX[s[r][c]];
}

// ShiftRows (FIPS-197, Section 5.1.2)
static inline void ShiftRows(AESState s)
{
    uint8_t t;
    // Row 1: shift left 1
    t = s[1][0]; s[1][0]=s[1][1]; s[1][1]=s[1][2]; s[1][2]=s[1][3]; s[1][3]=t;
    // Row 2: shift left 2
    t = s[2][0]; s[2][0]=s[2][2]; s[2][2]=t;
    t = s[2][1]; s[2][1]=s[2][3]; s[2][3]=t;
    // Row 3: shift left 3 (= right 1)
    t = s[3][3]; s[3][3]=s[3][2]; s[3][2]=s[3][1]; s[3][1]=s[3][0]; s[3][0]=t;
}

// InvShiftRows
static inline void InvShiftRows(AESState s)
{
    uint8_t t;
    // Row 1: shift right 1
    t = s[1][3]; s[1][3]=s[1][2]; s[1][2]=s[1][1]; s[1][1]=s[1][0]; s[1][0]=t;
    // Row 2: shift right 2
    t = s[2][0]; s[2][0]=s[2][2]; s[2][2]=t;
    t = s[2][1]; s[2][1]=s[2][3]; s[2][3]=t;
    // Row 3: shift right 3 (= left 1)
    t = s[3][0]; s[3][0]=s[3][1]; s[3][1]=s[3][2]; s[3][2]=s[3][3]; s[3][3]=t;
}

// MixColumns (FIPS-197, Section 5.1.3)
static inline void MixColumns(AESState s)
{
    for (int c = 0; c < 4; ++c) {
        uint8_t a0=s[0][c], a1=s[1][c], a2=s[2][c], a3=s[3][c];
        s[0][c] = gf_mul(0x02,a0) ^ gf_mul(0x03,a1) ^ a2 ^ a3;
        s[1][c] = a0 ^ gf_mul(0x02,a1) ^ gf_mul(0x03,a2) ^ a3;
        s[2][c] = a0 ^ a1 ^ gf_mul(0x02,a2) ^ gf_mul(0x03,a3);
        s[3][c] = gf_mul(0x03,a0) ^ a1 ^ a2 ^ gf_mul(0x02,a3);
    }
}

// InvMixColumns
static inline void InvMixColumns(AESState s)
{
    for (int c = 0; c < 4; ++c) {
        uint8_t a0=s[0][c], a1=s[1][c], a2=s[2][c], a3=s[3][c];
        s[0][c] = gf_mul(0x0e,a0) ^ gf_mul(0x0b,a1) ^ gf_mul(0x0d,a2) ^ gf_mul(0x09,a3);
        s[1][c] = gf_mul(0x09,a0) ^ gf_mul(0x0e,a1) ^ gf_mul(0x0b,a2) ^ gf_mul(0x0d,a3);
        s[2][c] = gf_mul(0x0d,a0) ^ gf_mul(0x09,a1) ^ gf_mul(0x0e,a2) ^ gf_mul(0x0b,a3);
        s[3][c] = gf_mul(0x0b,a0) ^ gf_mul(0x0d,a1) ^ gf_mul(0x09,a2) ^ gf_mul(0x0e,a3);
    }
}

// ----------------------------------------------------------------
//  SubWord / RotWord helpers for KeyExpansion
// ----------------------------------------------------------------
static inline uint32_t SubWord(uint32_t w)
{
    return ((uint32_t)SBOX[(w >> 24) & 0xff] << 24) |
           ((uint32_t)SBOX[(w >> 16) & 0xff] << 16) |
           ((uint32_t)SBOX[(w >>  8) & 0xff] <<  8) |
           ((uint32_t)SBOX[(w      ) & 0xff]);
}

static inline uint32_t RotWord(uint32_t w)
{
    return (w << 8) | (w >> 24);
}

// ----------------------------------------------------------------
//  AES class — supports 128 / 192 / 256
// ----------------------------------------------------------------
class AES {
public:
    // key_len_bytes: 16 (AES-128), 24 (AES-192), 32 (AES-256)
    explicit AES(const uint8_t* key, int key_len_bytes)
    {
        switch (key_len_bytes) {
            case 16: Nk_=4;  Nr_=10; break;
            case 24: Nk_=6;  Nr_=12; break;
            case 32: Nk_=8;  Nr_=14; break;
            default: throw std::invalid_argument(
                "AES key must be 16, 24, or 32 bytes");
        }
        key_len_ = key_len_bytes;
        KeyExpansion(key);
    }

    // Encrypt one 16-byte block (in-place)
    void EncryptBlock(const uint8_t* in, uint8_t* out) const
    {
        AESState s;
        BlockToState(in, s);
        AddRoundKey(s, rk_, 0);

        for (int round = 1; round < Nr_; ++round) {
            SubBytes(s);
            ShiftRows(s);
            MixColumns(s);
            AddRoundKey(s, rk_, round);
        }
        // Final round (no MixColumns)
        SubBytes(s);
        ShiftRows(s);
        AddRoundKey(s, rk_, Nr_);

        StateToBlock(s, out);
    }

    // Decrypt one 16-byte block (Equivalent Inverse Cipher)
    void DecryptBlock(const uint8_t* in, uint8_t* out) const
    {
        AESState s;
        BlockToState(in, s);
        AddRoundKey(s, rk_, Nr_);

        for (int round = Nr_-1; round >= 1; --round) {
            InvShiftRows(s);
            InvSubBytes(s);
            AddRoundKey(s, rk_, round);
            InvMixColumns(s);
        }
        InvShiftRows(s);
        InvSubBytes(s);
        AddRoundKey(s, rk_, 0);

        StateToBlock(s, out);
    }

    int KeyLen()    const { return key_len_; }
    int NumRounds() const { return Nr_; }

private:
    int Nk_, Nr_, key_len_;
    uint32_t rk_[60]; // max for AES-256: (14+1)*4=60

    // KeyExpansion (FIPS-197, Section 5.2)
    void KeyExpansion(const uint8_t* key)
    {
        int total_words = 4 * (Nr_ + 1);

        // Load original key words
        for (int i = 0; i < Nk_; ++i) {
            rk_[i] = ((uint32_t)key[4*i]   << 24) |
                     ((uint32_t)key[4*i+1]  << 16) |
                     ((uint32_t)key[4*i+2]  <<  8) |
                     ((uint32_t)key[4*i+3]);
        }

        for (int i = Nk_; i < total_words; ++i) {
            uint32_t temp = rk_[i - 1];
            if (i % Nk_ == 0)
                temp = SubWord(RotWord(temp)) ^ ((uint32_t)RCON[i / Nk_] << 24);
            else if (Nk_ > 6 && i % Nk_ == 4)
                temp = SubWord(temp);
            rk_[i] = rk_[i - Nk_] ^ temp;
        }
    }
};

// ----------------------------------------------------------------
//  CTR Mode (NIST SP 800-38A, Section 6.5)
//
//  Counter block layout (128-bit, big-endian counter):
//   [ Nonce (64 bits) | Counter (64 bits) ]
//  Counter starts at value in the supplied IV and increments
//  by 1 for each block (big-endian, 128-bit).
//
//  Encryption = Decryption (XOR with keystream).
//  No padding required.
// ----------------------------------------------------------------

// Increment a 128-bit counter in big-endian order.
// Returns normally if increment succeeds.
// Throws if the counter would overflow from FF..FF to 00..00.
static inline void IncrementCounterChecked(uint8_t* ctr) {
    for (int i = 15; i >= 0; --i) {
        if (ctr[i] == 0xff) {
            ctr[i] = 0x00;
        } else {
            ++ctr[i];
            return;
        }
    }

    throw std::runtime_error(
        "AES-CTR counter overflow: IV/counter space exhausted"
    );
}

/**
 * AES-CTR encrypt/decrypt (same operation).
 *
 * @param aes     Initialized AES object
 * @param iv      16-byte IV (nonce + initial counter)
 * @param in      Input bytes
 * @param in_len  Number of input bytes
 * @param out     Output buffer (must be >= in_len bytes)
 *
 * Endianness: counter is the full 128-bit IV incremented as a
 * big-endian integer (compatible with NIST SP 800-38A).
 */
static void AES_CTR_Process(
    const AES& aes,
    const uint8_t* iv,
    const uint8_t* in,
    size_t in_len,
    uint8_t* out
) {
    uint8_t counter[16];
    uint8_t keystream[16];

    std::memcpy(counter, iv, 16);

    size_t offset = 0;

    while (offset < in_len) {
        aes.EncryptBlock(counter, keystream);

        size_t chunk = std::min(static_cast<size_t>(16), in_len - offset);

        for (size_t i = 0; i < chunk; ++i) {
            out[offset + i] = in[offset + i] ^ keystream[i];
        }

        offset += chunk;

        // Only increment if another block is still needed.
        // This allows IV = FF..FF for exactly one final block,
        // but rejects longer inputs because the next counter would wrap.
        if (offset < in_len) {
            IncrementCounterChecked(counter);
        }
    }
}
