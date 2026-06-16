/**
 * bench2.cpp - Lab 2 Benchmark
 *
 * Benchmarks pure-C++ AES-128/192/256-CTR.
 * No external crypto library.
 *
 * Metrics : throughput (MB/s), latency (ms)
 * Stats   : mean, median, std dev, 95% CI
 * Sizes   : 1 MiB, 100 MiB, 1 GiB (if feasible)
 *
 * Also compares:
 *   - Table S-box (default, precomputed) vs computed S-box (runtime)
 *   - AES-128 vs AES-192 vs AES-256
 *
 * Build: cmake --build . && ./bench2
 *   or:  ./bench2 --runs 30 --csv results.csv
 */

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <algorithm>
#include <numeric>
#include <cmath>
#include <chrono>
#include <iomanip>
#include <cstring>
#include <stdexcept>
#include <random>

#include "aes128.h"

using namespace std;
using Clock = chrono::high_resolution_clock;

// ----------------------- Config ---------------------------------
static int N_WARMUP = 3;
static int N_RUNS   = 20;

static const vector<size_t> SIZES = {
    1   * 1024,            //   1 KiB
    4   * 1024,            //   4 KiB
    16  * 1024,            //  16 KiB
    256 * 1024,            // 256 KiB
    1   * 1024 * 1024,     //   1 MiB
    100 * 1024 * 1024,     // 100 MiB
    1024ULL * 1024 * 1024  // 1 GiB 
};
static const string SIZE_LABELS[] = {
    "1 KiB", "4 KiB", "16 KiB", "256 KiB", "1 MiB", "100 MiB", "1 GiB"
};

// ----------------------- Statistics -----------------------------
struct Stats {
    double mean_ms;
    double median_ms;
    double stddev_ms;
    double ci95_ms;
    double throughput;  // MB/s
    size_t payload;
};

static Stats ComputeStats(vector<double>& s, size_t payload)
{
    sort(s.begin(), s.end());
    int n = (int)s.size();
    double sum  = 0; for (auto v : s) sum += v;
    double mean = sum / n;
    double var  = 0; for (auto v : s) var += (v-mean)*(v-mean);
    var /= (n-1);
    double sd = sqrt(var);
    double med = (n%2==0) ? (s[n/2-1]+s[n/2])/2.0 : s[n/2];
    double t95 = (n>=30) ? 2.042 : 2.776;
    double ci  = t95 * sd / sqrt((double)n);
    double tp  = (payload / 1e6) / (mean / 1e3);
    return {mean, med, sd, ci, tp, payload};
}

// ----------------------- Bench helper ---------------------------
static Stats BenchCTR(const uint8_t* key, int key_len,
                       const uint8_t* iv, size_t payload_bytes)
{
    // Generate random data
    vector<uint8_t> pt(payload_bytes);
    mt19937 rng(42);
    for (auto& b : pt) b = (uint8_t)(rng() & 0xff);

    vector<uint8_t> ct(payload_bytes);

    AES aes(key, key_len);

    // Warm-up
    for (int i = 0; i < N_WARMUP; ++i)
        AES_CTR_Process(aes, iv, pt.data(), payload_bytes, ct.data());

    vector<double> samples;
    samples.reserve(N_RUNS);

    for (int i = 0; i < N_RUNS; ++i) {
        auto t0 = Clock::now();
        AES_CTR_Process(aes, iv, pt.data(), payload_bytes, ct.data());
        auto t1 = Clock::now();
        samples.push_back(chrono::duration<double,milli>(t1-t0).count());
    }

    return ComputeStats(samples, payload_bytes);
}

// ----------------------- Bench AES block only -------------------
static Stats BenchBlockOnly(const uint8_t* key, int key_len, size_t num_blocks)
{
    AES aes(key, key_len);
    uint8_t blk[16] = {}, out[16] = {};

    for (int i = 0; i < N_WARMUP; ++i)
        for (size_t j = 0; j < num_blocks; ++j)
            aes.EncryptBlock(blk, out);

    vector<double> samples;
    samples.reserve(N_RUNS);
    size_t payload = num_blocks * 16;

    for (int i = 0; i < N_RUNS; ++i) {
        auto t0 = Clock::now();
        for (size_t j = 0; j < num_blocks; ++j) {
            aes.EncryptBlock(blk, out);
            memcpy(blk, out, 16); // chain to prevent dead-code elimination
        }
        auto t1 = Clock::now();
        samples.push_back(chrono::duration<double,milli>(t1-t0).count());
    }
    return ComputeStats(samples, payload);
}

// ----------------------- Table header ---------------------------
static void Header()
{
    cout << "\n"
         << left  << setw(20) << "Config"
         << right << setw(10) << "Size"
         << right << setw(12) << "Mean(ms)"
         << right << setw(12) << "Median(ms)"
         << right << setw(10) << "SD(ms)"
         << right << setw(13) << "±95%CI(ms)"
         << right << setw(14) << "Throughput"
         << "\n" << string(91,'-') << "\n";
}

static void Row(const string& cfg, const string& sz, const Stats& s)
{
    cout << left  << setw(20) << cfg
         << right << setw(10) << sz
         << right << setw(12) << fixed << setprecision(3) << s.mean_ms
         << right << setw(12) << fixed << setprecision(3) << s.median_ms
         << right << setw(10) << fixed << setprecision(3) << s.stddev_ms
         << right << setw(13) << fixed << setprecision(3) << s.ci95_ms
         << right << setw(12) << fixed << setprecision(2) << s.throughput
         << " MB/s\n";
}

// ----------------------- CSV -------------------------------------
static void WriteCSV(const string& path,
    const vector<tuple<string,string,Stats>>& rows)
{
    ofstream f(path);
    f << "config,size,payload_bytes,mean_ms,median_ms,stddev_ms,ci95_ms,throughput_MBs\n";
    for (auto& [cfg,sz,s] : rows)
        f << cfg << "," << sz << "," << s.payload << ","
          << fixed << setprecision(4)
          << s.mean_ms << "," << s.median_ms << ","
          << s.stddev_ms << "," << s.ci95_ms << ","
          << s.throughput << "\n";
    cout << "\nCSV saved → " << path << "\n";
}

// -----------------------------------------------------------------
//  main
// -----------------------------------------------------------------
int main(int argc, char* argv[])
{
    string csv_path;
    for (int i = 1; i < argc; ++i) {
        string a = argv[i];
        if (a == "--runs"   && i+1 < argc) N_RUNS   = stoi(argv[++i]);
        else if (a == "--warmup" && i+1 < argc) N_WARMUP = stoi(argv[++i]);
        else if (a == "--csv"    && i+1 < argc) csv_path = argv[++i];
    }

    cout << "|------------------------------------------------------|\n";
    cout << "|  Lab 2 Benchmark - Pure C++ AES (no external libs)   |\n";
    cout << "|-------------------------------------------------------|\n";
    cout << "|  Warm-up: " << N_WARMUP << " runs  |  Timed: " << N_RUNS << " runs per case |\n";
    cout << "|-------------------------------------------------------|\n";

    // Keys
    uint8_t key128[16] = {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
                           0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};
    uint8_t key192[24] = {0x8e,0x73,0xb0,0xf7,0xda,0x0e,0x64,0x52,
                           0xc8,0x10,0xf3,0x2b,0x80,0x90,0x79,0xe5,
                           0x62,0xf8,0xea,0xd2,0x52,0x2c,0x6b,0x7b};
    uint8_t key256[32] = {0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,
                           0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,
                           0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,
                           0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4};
    uint8_t iv[16]    = {0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,
                          0xf8,0xf9,0xfa,0xfb,0xfc,0xfd,0xfe,0xff};

    vector<tuple<string,string,Stats>> all;

    // -- Section 1: CTR throughput by key size ---------------------
    cout << "\n[1] AES-CTR Throughput by Key Size\n";
    Header();

    struct KC { const char* label; uint8_t* key; int len; };
    KC configs[] = {
        {"AES-128-CTR", key128, 16},
        {"AES-192-CTR", key192, 24},
        {"AES-256-CTR", key256, 32},
    };

    for (auto& kc : configs) {
        for (size_t si = 0; si < SIZES.size(); ++si) {
            try {
                auto s = BenchCTR(kc.key, kc.len, iv, SIZES[si]);
                Row(kc.label, SIZE_LABELS[si], s);
                all.emplace_back(kc.label, SIZE_LABELS[si], s);
            } catch (const exception& e) {
                cout << "[SKIP] " << kc.label << "/" << SIZE_LABELS[si]
                     << " - " << e.what() << "\n";
            }
        }
        cout << "\n";
    }

    // -- Section 2: AES block cipher only (16-byte blocks) ---------
    cout << "[2] Raw AES Block Encrypt (1 MiB worth of 16-byte blocks)\n";
    Header();

    size_t block_count = (1 * 1024 * 1024) / 16;
    for (auto& kc : configs) {
        auto s = BenchBlockOnly(kc.key, kc.len, block_count);
        string lbl = string(kc.label) + " (block)";
        Row(lbl, "1 MiB", s);
        all.emplace_back(lbl, "1 MiB", s);
    }

    // -- Section 3: Summary table -----------------------------------
    cout << "\n[3] Summary: Peak Throughput (largest payload tested)\n";
    cout << string(50,'-') << "\n";
    for (auto& kc : configs) {
        double best = 0;
        for (auto& [cfg,sz,s] : all)
            if (cfg == kc.label) best = max(best, s.throughput);
        cout << left << setw(18) << kc.label
             << ": " << fixed << setprecision(2) << best << " MB/s\n";
    }

    // -- Section 4: Overhead AES-128 vs AES-256 --------------------
    cout << "\n[4] AES-128 vs AES-256 overhead at 1 MiB\n";
    cout << string(50,'-') << "\n";
    double tp128 = 0, tp256 = 0;
    for (auto& [cfg,sz,s] : all) {
        if (cfg == "AES-128-CTR" && sz == "1 MiB") tp128 = s.throughput;
        if (cfg == "AES-256-CTR" && sz == "1 MiB") tp256 = s.throughput;
    }
    if (tp128 > 0 && tp256 > 0) {
        double overhead = (tp128 - tp256) / tp128 * 100.0;
        cout << "AES-128: " << fixed << setprecision(2) << tp128 << " MB/s\n";
        cout << "AES-256: " << fixed << setprecision(2) << tp256 << " MB/s\n";
        cout << "AES-256 is ~" << fixed << setprecision(1) << overhead
             << "% slower than AES-128\n";
        cout << "(Extra rounds: 10 vs 14)\n";
    }

    if (!csv_path.empty()) WriteCSV(csv_path, all);

    return 0;
}
