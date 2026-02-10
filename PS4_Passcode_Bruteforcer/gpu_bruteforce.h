#pragma once

#include <string>
#include <cstdint>
#include <atomic>

struct PkgCryptoData {
    char content_id[37];          // 36-char Content ID + null terminator
    uint8_t expected_digest[32];  // Keys[0].digest = SHA256(dk0) XOR dk0 from ENTRY_KEYS
    bool valid = false;
};

// Returns true on success.
bool parse_pkg_crypto_data(const std::string& pkg_path, PkgCryptoData& out);

bool check_passcode(const PkgCryptoData& data, const char* passcode);

#ifdef USE_CUDA

// Check if a CUDA-capable GPU is available.
bool gpu_available();

// Get the number of CUDA GPUs.
int gpu_device_count();

// Get the name of a CUDA GPU by index.
std::string gpu_device_name(int device_id = 0);

// Run the GPU bruteforce loop across all available GPUs.
// Spawns one thread per GPU. Returns the found passcode or an empty string.
// Sets passcode_found to true when a match is discovered.
std::string gpu_brute_force(
    const PkgCryptoData& data,
    std::atomic<bool>& passcode_found,
    bool silence_mode,
    int batch_size_log2 = 23
);

#else

inline bool gpu_available() { return false; }
inline int gpu_device_count() { return 0; }
inline std::string gpu_device_name(int = 0) { return "N/A"; }
inline std::string gpu_brute_force(
    const PkgCryptoData&,
    std::atomic<bool>&,
    bool,
    int = 23
) { return ""; }

#endif
