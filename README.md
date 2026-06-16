# Lab 2 — AES-128 Pure C++ (FIPS-197, CTR Mode)

> **Constraint**: No external crypto library. STL only.

## File Structure

```
lab2/
├── aes128.h        — AES-128/192/256 core + CTR mode (header-only)
├── aestool.cpp     — CLI tool
├── bench.cpp      — Benchmark tool
├── nist_vectors.json — FIPS-197 + NIST SP 800-38A KAT vectors
├── CMakeLists.txt
└── README.md
```

## Dependencies

| Item | Requirement |
|---|---|
| C++ compiler | GCC ≥ 11 / MSVC 2019 / Clang ≥ 13 |
| CMake | ≥ 3.16 |
| External crypto lib | **None** |

## Build

```bash
mkdir build && cd build
cmake ..
cmake --build .
```

## Usage

### Key generation
```bash
./aestool keygen --bits 128 --out key.bin    # AES-128
./aestool keygen --bits 192 --out key.bin    # AES-192 (bonus)
./aestool keygen --bits 256 --out key.bin    # AES-256 (bonus)
```

### IV generation
```bash
./aestool geniv --out iv.bin
```

### Encrypt
```bash
./aestool encrypt --mode ctr --key key.bin --iv iv.bin --in plain.txt --out ct.bin
```

### Decrypt
```bash
./aestool decrypt --mode ctr --key key.bin --iv iv.bin --in ct.bin --out plain.txt
```

### Inline hex
```bash
./aestool encrypt --mode ctr \
  --key-hex 2b7e151628aed2a6abf7158809cf4f3c \
  --iv-hex  f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff \
  --text "hello world" --out ct.bin --encode hex
```

### KAT runner
```bash
./aestool --kat nist_vectors.json
```

### Benchmark
```bash
./bench
./bench --runs 100 --csv results.csv
```

## CTR Mode Details

- Counter block: 128-bit (nonce ∥ counter), big-endian increment
- IV must be exactly 16 bytes
- No padding required (stream cipher)
- Encrypt = Decrypt (XOR with keystream)
- **IV must be unique per key** — reuse destroys confidentiality

## Known Limitations

- CTR mode provides confidentiality only (no authentication)
- `std::random_device` is used for key/IV generation; on some
  Windows builds this may not be a true CSPRNG
- No constant-time S-box (susceptible to cache-timing attacks)
