#pragma once

#include <string>
#include <cstdint>
#include <atomic>

// Data extracted from a PS4 PKG file needed for GPU-accelerated passcode bruteforce.
// Obtained by parsing the PKG header and ENTRY_KEYS entry.
struct PkgCryptoData {
    char content_id[37];          // 36-char Content ID + null terminator
    uint8_t expected_digest[32];  // Keys[0].digest from the ENTRY_KEYS entry
    bool valid = false;
};

// Parse a PS4 PKG file and extract the crypto data needed for GPU bruteforce.
// Returns true on success.
bool parse_pkg_crypto_data(const std::string& pkg_path, PkgCryptoData& out);

#ifdef USE_CUDA

// Check if a CUDA-capable GPU is available.
bool gpu_available();

// Get the name of the first CUDA GPU.
std::string gpu_device_name();

// Run the GPU bruteforce loop. Returns the found passcode or an empty string.
// Sets passcode_found to true when a match is discovered.
std::string gpu_brute_force(
    const PkgCryptoData& data,
    std::atomic<bool>& passcode_found,
    bool silence_mode,
    int batch_size_log2 = 23 // 2^23 = ~8M passcodes per kernel launch
);

#else

inline bool gpu_available() { return false; }
inline std::string gpu_device_name() { return "N/A"; }
inline std::string gpu_brute_force(
    const PkgCryptoData&,
    std::atomic<bool>&,
    bool,
    int = 23
) { return ""; }

#endif
