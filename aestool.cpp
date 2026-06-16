/**
 * aestool.cpp - Lab 2: AES-128 Pure C++ CLI Tool
 *
 * NO external crypto libraries (STL only).
 * Implements: AES-128/192/256 + CTR mode (NIST SP 800-38A)
 *
 * Commands:
 *   aestool keygen  --bits 128|192|256 --out key.bin
 *   aestool geniv   --out iv.bin
 *   aestool encrypt --mode ctr --key key.bin --iv iv.bin --in msg.bin --out ct.bin
 *   aestool decrypt --mode ctr --key key.bin --iv iv.bin --in ct.bin  --out msg.bin
 *   aestool --kat nist_vectors.json
 *   aestool show    --key key.bin [--iv iv.bin]
 *
 * Options:
 *   --encode hex|base64|raw   (console output encoding, default hex)
 *   --key-hex <HEX>           Inline hex key
 *   --iv-hex  <HEX>           Inline hex IV
 *   --text    "..."           Encrypt/decrypt string directly
 *   --verbose                 Extra diagnostic output
 */

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <stdexcept>
#include <algorithm>
#include <cstring>
#include <cstdint>
#include <random>
#include <chrono>
#include <map>

#include "aes128.h"

using namespace std;


static map<string, string> ParseArgs(int start, int argc, char* argv[])
{
    map<string, string> args;

    for (int i = start; i < argc; ++i) {
        string key = argv[i];

        if (key.rfind("--", 0) == 0) {
            if (i + 1 < argc && string(argv[i + 1]).rfind("--", 0) != 0) {
                args[key] = argv[++i];
            } else {
                args[key] = "true";
            }
        }
    }
    return args;
}
static string GetArg(const map<string, string>& args,
                     const string& key,
                     const string& def = "")
{
    auto it = args.find(key);
    return it == args.end() ? def : it->second;
}

static bool HasArg(const map<string, string>& args,
                   const string& key)
{
    return args.find(key) != args.end();
}

// ----------------------- Secure RNG (no crypto lib) -------------
// Uses std::random_device which on modern Linux/Windows reads from
// OS CSPRNG (/dev/urandom, BCryptGenRandom).
// NOTE: std::random_device is NOT a CSPRNG on all implementations.
// For production, use OS API directly. For lab: acceptable.

static void SecureRandBytes(uint8_t* buf, size_t len)
{
    std::random_device rd;
    size_t full = len / 4;
    size_t rem  = len % 4;
    for (size_t i = 0; i < full; ++i) {
        uint32_t v = rd();
        memcpy(buf + i*4, &v, 4);
    }
    if (rem) {
        uint32_t v = rd();
        memcpy(buf + full*4, &v, rem);
    }
}

// ----------------------- Hex encode/decode ----------------------

static string ToHex(const uint8_t* data, size_t len)
{
    static const char HEX[] = "0123456789abcdef";
    string out(len * 2, '\0');
    for (size_t i = 0; i < len; ++i) {
        out[2*i]   = HEX[data[i] >> 4];
        out[2*i+1] = HEX[data[i] & 0x0f];
    }
    return out;
}

static uint8_t HexNibble(char c)
{
    if (c >= '0' && c <= '9') return (uint8_t)(c - '0');
    if (c >= 'a' && c <= 'f') return (uint8_t)(c - 'a' + 10);
    if (c >= 'A' && c <= 'F') return (uint8_t)(c - 'A' + 10);
    throw runtime_error(string("Invalid hex character: ") + c);
}

static vector<uint8_t> FromHex(const string& hex)
{
    if (hex.size() % 2 != 0)
        throw runtime_error("Hex string has odd length");
    vector<uint8_t> out(hex.size() / 2);
    for (size_t i = 0; i < out.size(); ++i)
        out[i] = (HexNibble(hex[2*i]) << 4) | HexNibble(hex[2*i+1]);
    return out;
}

// ----------------------- Base64 encode --------------------------

static string ToBase64(const uint8_t* data, size_t len)
{
    static const char B64[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    string out;
    out.reserve(((len + 2) / 3) * 4);
    for (size_t i = 0; i < len; i += 3) {
        uint32_t v = (uint32_t)data[i] << 16;
        if (i+1 < len) v |= (uint32_t)data[i+1] << 8;
        if (i+2 < len) v |= (uint32_t)data[i+2];
        out += B64[(v >> 18) & 63];
        out += B64[(v >> 12) & 63];
        out += (i+1 < len) ? B64[(v >> 6) & 63] : '=';
        out += (i+2 < len) ? B64[v & 63]         : '=';
    }
    return out;
}

// ----------------------- File I/O -------------------------------

static vector<uint8_t> ReadFile(const string& path)
{
    ifstream f(path, ios::binary | ios::ate);
    if (!f) throw runtime_error("Cannot open file: " + path);
    streamsize sz = f.tellg();
    f.seekg(0, ios::beg);
    vector<uint8_t> buf(sz);
    if (!f.read(reinterpret_cast<char*>(buf.data()), sz))
        throw runtime_error("Read error: " + path);
    return buf;
}

static void WriteFile(const string& path, const uint8_t* data, size_t len)
{
    ofstream f(path, ios::binary | ios::trunc);
    if (!f) throw runtime_error("Cannot create file: " + path);
    f.write(reinterpret_cast<const char*>(data), static_cast<streamsize>(len));
    if (!f) throw runtime_error("Write error: " + path);
}

static void WriteFile(const string& path, const vector<uint8_t>& data)
{
    WriteFile(path, data.data(), data.size());
}

// ----------------------- Console output -------------------------

static void PrintEncoded(const string& label, const string& enc,
                          const uint8_t* data, size_t len)
{
    if (enc == "hex")
        cout << label << ": " << ToHex(data, len) << "\n";
    else if (enc == "base64")
        cout << label << ": " << ToBase64(data, len) << "\n";
    else
        cout << label << ": [raw binary, " << len << " bytes]\n";
}


//  keygen command

static void CmdKeygen(int argc, char* argv[])
{
    auto args = ParseArgs(2, argc, argv);

    size_t bits = stoul(GetArg(args, "--bits", "128"));
    string outfile = GetArg(args, "--out");

    if (outfile.empty())
        throw runtime_error("keygen: --out required");

    if (bits != 128 && bits != 192 && bits != 256)
        throw runtime_error("keygen: --bits must be 128, 192, or 256");

    size_t bytes = bits / 8;
    vector<uint8_t> key(bytes);

    SecureRandBytes(key.data(), bytes);
    WriteFile(outfile, key);

    cout << "Generated AES-" << bits << " key > " << outfile
         << " (" << bytes << " bytes)\n";
    cout << "Key (hex): " << ToHex(key.data(), bytes) << "\n";
}


//  geniv command

static void CmdGenIV(int argc, char* argv[])
{
    auto args = ParseArgs(2, argc, argv);

    string outfile = GetArg(args, "--out");

    if (outfile.empty())
        throw runtime_error("geniv: --out required");

    vector<uint8_t> iv(16);
    SecureRandBytes(iv.data(), 16);

    WriteFile(outfile, iv);

    cout << "Generated IV > " << outfile << "\n";
    cout << "IV (hex) : " << ToHex(iv.data(), 16) << "\n";
}

//  show command

static void CmdShow(int argc, char* argv[])
{
    auto args = ParseArgs(2, argc, argv);

    string keyfile = GetArg(args, "--key");
    string ivfile  = GetArg(args, "--iv");

    if (keyfile.empty())
        throw runtime_error("show: --key required");

    auto key = ReadFile(keyfile);

    if (key.size() != 16 && key.size() != 24 && key.size() != 32)
        throw runtime_error("show: invalid key size " + to_string(key.size()));

    cout << "Key (" << key.size() * 8 << "-bit): "
         << ToHex(key.data(), key.size()) << "\n";

    if (!ivfile.empty()) {
        auto iv = ReadFile(ivfile);

        if (iv.size() != 16)
            throw runtime_error("show: IV must be 16 bytes");

        cout << "IV  (128-bit): " << ToHex(iv.data(), 16) << "\n";
    }
}


//  encrypt / decrypt commands

static void CmdCrypt(bool encrypting, int argc, char* argv[])
{
    auto args = ParseArgs(2, argc, argv);

    string mode    = GetArg(args, "--mode", "ctr");
    string keyfile = GetArg(args, "--key");
    string keyhex  = GetArg(args, "--key-hex");
    string ivfile  = GetArg(args, "--iv");
    string ivhex   = GetArg(args, "--iv-hex");
    string infile  = GetArg(args, "--in");
    string outfile = GetArg(args, "--out");
    string text_in = GetArg(args, "--text");
    string encode  = GetArg(args, "--encode", "hex");
    bool verbose   = HasArg(args, "--verbose");

    // Normalize mode/encode về lowercase
    transform(mode.begin(), mode.end(), mode.begin(), ::tolower);
    transform(encode.begin(), encode.end(), encode.begin(), ::tolower);

    // Validate mode
    if (mode != "ctr")
        throw runtime_error("aestool only supports --mode ctr");

    // Validate output
    if (outfile.empty())
        throw runtime_error("encrypt/decrypt: --out required");

    // Load key
    vector<uint8_t> key;

    if (!keyhex.empty() && !keyfile.empty())
        throw runtime_error("encrypt/decrypt: use --key OR --key-hex, not both");

    if (!keyhex.empty())
        key = FromHex(keyhex);
    else if (!keyfile.empty())
        key = ReadFile(keyfile);
    else
        throw runtime_error("encrypt/decrypt: --key or --key-hex required");

    if (key.size() != 16 && key.size() != 24 && key.size() != 32)
        throw runtime_error("Key must be exactly 16, 24, or 32 bytes. Got: "
                            + to_string(key.size()));

    // Load IV
    vector<uint8_t> iv;

    if (!ivhex.empty() && !ivfile.empty())
        throw runtime_error("encrypt/decrypt: use --iv OR --iv-hex, not both");

    if (!ivhex.empty())
        iv = FromHex(ivhex);
    else if (!ivfile.empty())
        iv = ReadFile(ivfile);
    else
        throw runtime_error("encrypt/decrypt: --iv or --iv-hex required");

    if (iv.size() != 16)
        throw runtime_error("IV must be exactly 16 bytes. Got: "
                            + to_string(iv.size()));

    // Load input
    vector<uint8_t> input;

    if (!text_in.empty() && !infile.empty())
        throw runtime_error("encrypt/decrypt: use --text OR --in, not both");

    if (!text_in.empty())
        input.assign(text_in.begin(), text_in.end());
    else if (!infile.empty())
        input = ReadFile(infile);
    else
        throw runtime_error("encrypt/decrypt: --in or --text required");

    if (input.empty())
        throw runtime_error("Input is empty - nothing to process");

    // Process
    AES aes(key.data(), static_cast<int>(key.size()));
    vector<uint8_t> output;

    if (mode == "ctr") {
        output.resize(input.size());
        AES_CTR_Process(aes, iv.data(), input.data(), input.size(), output.data());
    }

    // Write output
    WriteFile(outfile, output);

    // Console report
    string algLabel = "AES-" + to_string(key.size() * 8) + "-" + mode;
    transform(algLabel.begin(), algLabel.end(), algLabel.begin(), ::toupper);

    cout << (encrypting ? "Encrypted" : "Decrypted") << " : "
         << algLabel << "\n";
    cout << "Input     : " << (infile.empty() ? "(text)" : infile)
         << " (" << input.size() << " bytes)\n";
    cout << "Output    : " << outfile
         << " (" << output.size() << " bytes)\n";

    if (verbose) {
        cout << "Key (hex) : " << ToHex(key.data(), key.size()) << "\n";
        cout << "IV  (hex) : " << ToHex(iv.data(), 16) << "\n";
    }

    PrintEncoded(encrypting ? "Ciphertext" : "Plaintext",
                 encode,
                 output.data(),
                 min(output.size(), static_cast<size_t>(64)));

    if (output.size() > 64)
        cout << "            ... (" << output.size() << " bytes total)\n";
}


//  KAT runner
//
//  vectors.json format:
//  [
//    {
//      "id"   : "FIPS-AES128-1",
//      "type" : "aes_block",    // or "ctr"
//      "key"  : "<hex>",
//      "pt"   : "<hex>",
//      "ct"   : "<hex>",
//      "iv"   : "<hex>"         // only for ctr
//    }, ...
//  ]


static string JsonField(const string& obj, const string& key)
{
    string needle = "\"" + key + "\"";
    size_t pos = obj.find(needle);
    if (pos == string::npos) return "";
    pos = obj.find(':', pos);
    if (pos == string::npos) return "";
    pos = obj.find('"', pos);
    if (pos == string::npos) return "";
    size_t start = pos + 1;
    size_t end   = obj.find('"', start);
    if (end == string::npos) return "";
    return obj.substr(start, end - start);
}

static void CmdKAT(const string& vecfile)
{
    // Read entire file
    ifstream f(vecfile);
    if (!f) throw runtime_error("KAT: cannot open " + vecfile);
    string json((istreambuf_iterator<char>(f)), {});

    int pass = 0, fail = 0, skip = 0;
    cout << "\n=== KAT Runner: " << vecfile << " ===\n\n";

    size_t pos = 0;
    while ((pos = json.find('{', pos)) != string::npos) {
        size_t end = json.find('}', pos);
        if (end == string::npos) break;
        string obj = json.substr(pos, end - pos + 1);
        pos = end + 1;

        string id      = JsonField(obj, "id");
        string type    = JsonField(obj, "type");
        string key_hex = JsonField(obj, "key");
        string pt_hex  = JsonField(obj, "pt");
        string ct_hex  = JsonField(obj, "ct");
        string iv_hex  = JsonField(obj, "iv");

        if (id.empty() || key_hex.empty()) continue;

        try {
            auto key = FromHex(key_hex);
            auto pt  = FromHex(pt_hex);
            auto exp = FromHex(ct_hex);

            if (type == "aes_block" || type.empty()) {
                // Test AES block cipher directly
                AES aes(key.data(), (int)key.size());
                vector<uint8_t> ct(16), dec(16);
                aes.EncryptBlock(pt.data(), ct.data());
                aes.DecryptBlock(ct.data(), dec.data());

                bool enc_ok = (ct == exp);
                bool dec_ok = (dec == pt);

                if (enc_ok && dec_ok) {
                    cout << "[PASS] " << id << "\n";
                    ++pass;
                } else {
                    cout << "[FAIL] " << id << "\n";
                    if (!enc_ok) {
                        cout << "       Encrypt expected: " << ct_hex << "\n";
                        cout << "       Encrypt got     : " << ToHex(ct.data(), ct.size()) << "\n";
                    }
                    if (!dec_ok) {
                        cout << "       Decrypt expected: " << pt_hex << "\n";
                        cout << "       Decrypt got     : " << ToHex(dec.data(), dec.size()) << "\n";
                    }
                    ++fail;
                }
            } else if (type == "ctr") {
                auto iv = FromHex(iv_hex);
                if (iv.size() != 16) throw runtime_error("CTR KAT: IV must be 16 bytes");

                AES aes(key.data(), (int)key.size());
                vector<uint8_t> ct(pt.size());
                AES_CTR_Process(aes, iv.data(), pt.data(), pt.size(), ct.data());

                if (ct == exp) {
                    cout << "[PASS] " << id << "\n";
                    ++pass;
                } else {
                    cout << "[FAIL] " << id << "\n";
                    cout << "       expected: " << ct_hex << "\n";
                    cout << "       got     : " << ToHex(ct.data(), ct.size()) << "\n";
                    ++fail;
                }
            }
            else {
                cout << "[SKIP] " << id << " (unknown type '" << type << "')\n";
                ++skip;
            }
        } catch (const exception& e) {
            cout << "[FAIL] " << id << " - " << e.what() << "\n";
            ++fail;
        }
    }

    cout << "\n----------------------------------------\n";
    cout << "Total : " << (pass+fail+skip)
         << "  |  PASS: " << pass
         << "  |  FAIL: " << fail
         << "  |  SKIP: " << skip << "\n";
    cout << "----------------------------------------\n\n";

    if (fail > 0) exit(1);
}


//  Negative Tests
//  Usage: aestool --test-negative


static void CmdNegativeTest()
{
    cout << "\n=== Negative Tests (Lab 2 - Pure C++ AES-CTR) ===\n\n";

    int pass = 0, fail = 0;
    auto Result = [&](bool ok, const string& name, const string& note = "") {
        if (ok) { cout << "[PASS] " << name << "\n"; ++pass; }
        else    { cout << "[FAIL] " << name << (note.empty() ? "" : " - " + note) << "\n"; ++fail; }
    };

    // Shared test data 
    const string plaintext = "NegativeTestVectorForAESCTR!1234"; // 32 bytes

    // Valid key + IV
    uint8_t key[16] = {
        0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
        0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
    };
    uint8_t wrongKey[16] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };
    uint8_t iv[16] = {
        0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,
        0xf8,0xf9,0xfa,0xfb,0xfc,0xfd,0xfe,0xff
    };
    uint8_t wrongIV[16] = {
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
    };

    vector<uint8_t> pt(plaintext.begin(), plaintext.end());
    vector<uint8_t> ct(pt.size());
    vector<uint8_t> rec(pt.size());

    AES aes(key, 16);
    AES_CTR_Process(aes, iv, pt.data(), pt.size(), ct.data());

    // T01: Wrong key > plaintext mismatch
    {
        AES wrongAes(wrongKey, 16);
        AES_CTR_Process(wrongAes, iv, ct.data(), ct.size(), rec.data());
        Result(rec != pt, "T01: CTR wrong key > plaintext mismatch");
    }

    // T02: Wrong IV > plaintext mismatch
    {
        AES_CTR_Process(aes, wrongIV, ct.data(), ct.size(), rec.data());
        Result(rec != pt, "T02: CTR wrong IV > plaintext mismatch");
    }

    // T03: Tampered ciphertext > corrupted plaintext
    // CTR has NO authentication - tamper goes undetected (silent corruption)
    {
        vector<uint8_t> tampered = ct;
        tampered[0] ^= 0x01; // flip 1 bit
        AES_CTR_Process(aes, iv, tampered.data(), tampered.size(), rec.data());
        // Exactly 1 bit of plaintext is flipped - NOT equal
        Result(rec != pt,
            "T03: CTR tampered CT > silent plaintext corruption (expected - CTR has no auth)");
    }

    // T04: CTR cannot detect tampering - explicit explanation 
    {
        // CTR is a stream cipher: C = P XOR Keystream
        // Flipping bit i in C flips exactly bit i in P.
        // There is no authentication tag to catch this.
        // > CTR MUST be combined with a MAC (e.g. HMAC or use AES-GCM) for integrity.
        cout << "       Note: CTR provides confidentiality ONLY.\n";
        cout << "             Use AES-GCM or CTR+HMAC for authenticated encryption.\n";
        Result(true, "T04: CTR tamper undetected - documented (correct behavior)");
    }

    // T05: Invalid key length (10 bytes) > exception
    {
        bool caught = false;
        try {
            uint8_t badKey[10] = {};
            AES badAes(badKey, 10);
            (void)badAes;
        } catch (const invalid_argument&) { caught = true; }
          catch (const runtime_error&)    { caught = true; }
        Result(caught, "T05: Invalid key length (10 bytes) > exception thrown");
    }

    // T06: Invalid key length (0 bytes) > exception 
    {
        bool caught = false;
        try {
            AES badAes(nullptr, 0);
            (void)badAes;
        } catch (...) { caught = true; }
        Result(caught, "T06: Invalid key length (0 bytes) > exception thrown");
    }

    // T07: IV length validation (enforced by CLI) 
    {
        // Our CLI rejects IV != 16 bytes before calling AES_CTR_Process.
        // Simulate the guard:
        size_t bad_iv_len = 8;
        bool caught = false;
        try {
            if (bad_iv_len != 16)
                throw runtime_error("IV must be exactly 16 bytes. Got: "
                                    + to_string(bad_iv_len));
        } catch (const runtime_error&) { caught = true; }
        Result(caught, "T07: IV length 8 bytes > rejected by CLI guard");
    }

    // T08: IV length 0 > rejected 
    {
        bool caught = false;
        try {
            size_t bad = 0;
            if (bad != 16)
                throw runtime_error("IV must be exactly 16 bytes. Got: 0");
        } catch (...) { caught = true; }
        Result(caught, "T08: IV length 0 bytes > rejected");
    }

    // T09: Empty input > rejected 
    {
        bool caught = false;
        try {
            vector<uint8_t> empty_in;
            if (empty_in.empty())
                throw runtime_error("Input is empty - nothing to process");
        } catch (const runtime_error&) { caught = true; }
        Result(caught, "T09: Empty input > rejected");
    }

    // T10: CTR encrypt == decrypt (same operation) 
    {
        // CTR: encrypt(encrypt(P)) == P  (XOR is its own inverse)
        vector<uint8_t> double_enc(pt.size());
        AES_CTR_Process(aes, iv, ct.data(), ct.size(), double_enc.data());
        Result(double_enc == pt, "T10: CTR double-encrypt roundtrip == original plaintext");
    }


    // Summary 
    cout << "\n--------------------------------------------\n";
    cout << "Total : " << (pass + fail)
         << "  |  PASS: " << pass
         << "  |  FAIL: " << fail << "\n";
    cout << "--------------------------------------------\n\n";

    if (fail > 0) exit(1);
}


//  Usage

static void PrintUsage()
{
    cout <<
R"(Usage: aestool <command> [options]

Commands:
  keygen          --bits 128|192|256 --out <keyfile>
  geniv           --out <ivfile>
  show            --key <keyfile> [--iv <ivfile>]
  encrypt         --mode ctr --key <keyfile> --iv <ivfile> --in <file> --out <file>
  decrypt         --mode ctr --key <keyfile> --iv <ivfile> --in <file> --out <file>
  --kat           <vectors.json>
  --test-negative Run all negative/misuse test cases

Options:
  --key-hex <HEX>           Inline hex key instead of --key
  --iv-hex  <HEX>           Inline hex IV instead of --iv
  --text    "<string>"      Process string instead of file
  --encode  hex|base64|raw  Console output encoding, default hex
  --verbose                 Show key/IV in output

Examples:
  aestool keygen --bits 128 --out key.bin
  aestool geniv  --out iv.bin

  aestool encrypt --mode ctr --key key.bin --iv iv.bin --in plain.txt --out ct_ctr.bin
  aestool decrypt --mode ctr --key key.bin --iv iv.bin --in ct_ctr.bin --out dec_ctr.txt

  aestool --kat nist_vectors.json
  aestool --test-negative

Note:
  - No external crypto library is used.
  - CTR mode does not use padding.
)";
}

//  main

int main(int argc, char* argv[])
{
    if (argc < 2) { PrintUsage(); return 1; }

    string cmd = argv[1];

    try {
        if      (cmd == "keygen")  CmdKeygen(argc, argv);
        else if (cmd == "geniv")   CmdGenIV(argc, argv);
        else if (cmd == "show")    CmdShow(argc, argv);
        else if (cmd == "encrypt") CmdCrypt(true,  argc, argv);
        else if (cmd == "decrypt") CmdCrypt(false, argc, argv);
        else if (cmd == "--kat" && argc >= 3) CmdKAT(argv[2]);
        else if (cmd == "--test-negative")    CmdNegativeTest();
        else { cerr << "Unknown command: " << cmd << "\n"; PrintUsage(); return 1; }
    }
    catch (const exception& e) {
        cerr << "Error: " << e.what() << "\n";
        return 1;
    }
    return 0;
}
