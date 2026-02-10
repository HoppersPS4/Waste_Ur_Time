#include "gpu_bruteforce.h"

#include <cuda_runtime.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <chrono>
#include <iostream>
#include <iomanip>
#include <random>
#include <thread>
#include <mutex>
#include <vector>


#define HASHES_PER_THREAD 4 // 4 for now but 

static constexpr float AUTOTUNE_TARGET_MS_LOW  = 30.0f; 
static constexpr float AUTOTUNE_TARGET_MS_HIGH = 100.0f; 
static constexpr int   AUTOTUNE_MIN_LOG2       = 18;     // 256K threads minimum
static constexpr int   AUTOTUNE_MAX_LOG2        = 28;    // 256M threads maximum

//sha256 constants (host and device)

static const uint32_t h_K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

__device__ __constant__ uint32_t d_K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

__device__ __constant__ uint32_t d_H0[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

__device__ __constant__ char d_CHARSET[64] = {
    '0','1','2','3','4','5','6','7','8','9',
    'a','b','c','d','e','f','g','h','i','j',
    'k','l','m','n','o','p','q','r','s','t',
    'u','v','w','x','y','z',
    'A','B','C','D','E','F','G','H','I','J',
    'K','L','M','N','O','P','Q','R','S','T',
    'U','V','W','X','Y','Z',
    '-','_'
};



__device__ __forceinline__ uint32_t d_rotr(uint32_t x, int n) {
    return (x >> n) | (x << (32 - n));
}

// LOP3 instructions: combine 3 logical ops into 1 GPU cycle via PTX
// Ch truth table:  (x & y) ^ (~x & z) = 0xCA
// Maj truth table: (x & y) ^ (x & z) ^ (y & z) = 0xE8
#ifdef __CUDACC__                       // nvcc – use real PTX
__device__ __forceinline__ uint32_t d_ch(uint32_t x, uint32_t y, uint32_t z) {
    uint32_t result;
    asm("lop3.b32 %0, %1, %2, %3, 0xCA;" : "=r"(result) : "r"(x), "r"(y), "r"(z));
    return result;
}
__device__ __forceinline__ uint32_t d_maj(uint32_t x, uint32_t y, uint32_t z) {
    uint32_t result;
    asm("lop3.b32 %0, %1, %2, %3, 0xE8;" : "=r"(result) : "r"(x), "r"(y), "r"(z));
    return result;
}
#else                                   // IntelliSense / plain C++ fallback
__device__ __forceinline__ uint32_t d_ch(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (~x & z);
}
__device__ __forceinline__ uint32_t d_maj(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}
#endif

__device__ __forceinline__ uint32_t d_Sigma0(uint32_t x) {
    return d_rotr(x, 2) ^ d_rotr(x, 13) ^ d_rotr(x, 22);
}

__device__ __forceinline__ uint32_t d_Sigma1(uint32_t x) {
    return d_rotr(x, 6) ^ d_rotr(x, 11) ^ d_rotr(x, 25);
}

__device__ __forceinline__ uint32_t d_sigma0(uint32_t x) {
    return d_rotr(x, 7) ^ d_rotr(x, 18) ^ (x >> 3);
}

__device__ __forceinline__ uint32_t d_sigma1(uint32_t x) {
    return d_rotr(x, 17) ^ d_rotr(x, 19) ^ (x >> 10);
}


__device__ void sha256_transform(uint32_t state[8], const uint32_t block[16]) {
    uint32_t W[16];
    #pragma unroll
    for (int i = 0; i < 16; i++) W[i] = block[i];

    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t e = state[4], f = state[5], g = state[6], h = state[7];

    for (int i = 0; i < 64; i++) {
        uint32_t w;
        if (i < 16) {
            w = W[i];
        } else {
            w = d_sigma1(W[(i - 2) & 15]) + W[(i - 7) & 15]
              + d_sigma0(W[(i - 15) & 15]) + W[(i - 16) & 15];
            W[i & 15] = w;
        }

        uint32_t T1 = h + d_Sigma1(e) + d_ch(e, f, g) + d_K[i] + w;
        uint32_t T2 = d_Sigma0(a) + d_maj(a, b, c);
        h = g; g = f; f = e; e = d + T1;
        d = c; c = b; b = a; a = T1 + T2;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}


__device__ __forceinline__ uint64_t xorshift64star(uint64_t* s) {
    uint64_t x = *s;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    *s = x;
    return x * 0x2545F4914F6CDD1DULL;
}


__global__ void check_passcodes_kernel(
    const uint32_t* __restrict__ midstate,          // [8] SHA-256 state after 1st block
    const uint32_t* __restrict__ expected_digest,   // [8] Keys[0].digest as BE uint32
    uint64_t                     base_seed,
    int*            __restrict__ found_flag,
    uint8_t*        __restrict__ found_passcode)
{
    if (*found_flag) return;

    const uint32_t tid = blockIdx.x * blockDim.x + threadIdx.x;

    #pragma unroll
    for (int attempt = 0; attempt < HASHES_PER_THREAD; attempt++) {
        if (*found_flag) return;

        uint64_t rng = base_seed ^ (((uint64_t)tid * HASHES_PER_THREAD + attempt)
                       * 6364136223846793005ULL + 1442695040888963407ULL);
        xorshift64star(&rng);
        xorshift64star(&rng);

        uint8_t passcode[32];
        {
            uint64_t r0 = xorshift64star(&rng);
            uint64_t r1 = xorshift64star(&rng);
            uint64_t r2 = xorshift64star(&rng);
            uint64_t r3 = xorshift64star(&rng);
            #pragma unroll
            for (int i = 0; i < 8; i++) {
                passcode[i]      = d_CHARSET[(r0 >> (i * 8)) & 0x3F];
                passcode[8 + i]  = d_CHARSET[(r1 >> (i * 8)) & 0x3F];
                passcode[16 + i] = d_CHARSET[(r2 >> (i * 8)) & 0x3F];
                passcode[24 + i] = d_CHARSET[(r3 >> (i * 8)) & 0x3F];
            }
        }

        uint32_t block2[16];
        #pragma unroll
        for (int i = 0; i < 8; i++) {
            block2[i] = ((uint32_t)passcode[i * 4    ] << 24)
                      | ((uint32_t)passcode[i * 4 + 1] << 16)
                      | ((uint32_t)passcode[i * 4 + 2] <<  8)
                      | ((uint32_t)passcode[i * 4 + 3]);
        }
        block2[8]  = 0x80000000u;
        block2[9]  = 0; block2[10] = 0; block2[11] = 0;
        block2[12] = 0; block2[13] = 0; block2[14] = 0;
        block2[15] = 0x00000300u; // 96 * 8 = 768 bits

        uint32_t state[8];
        #pragma unroll
        for (int i = 0; i < 8; i++) state[i] = midstate[i];

        sha256_transform(state, block2);

        // dk0 digest: SHA256(dk0) where dk0 = state after transform
        uint32_t dk0_block[16];
        #pragma unroll
        for (int i = 0; i < 8; i++) dk0_block[i] = state[i];
        dk0_block[8]  = 0x80000000u;
        dk0_block[9]  = 0; dk0_block[10] = 0; dk0_block[11] = 0;
        dk0_block[12] = 0; dk0_block[13] = 0; dk0_block[14] = 0;
        dk0_block[15] = 0x00000100u; // 32 * 8 = 256 bits

        uint32_t sha_dk0[8];
        #pragma unroll
        for (int i = 0; i < 8; i++) sha_dk0[i] = d_H0[i];

        sha256_transform(sha_dk0, dk0_block);

        // early exit if first 32 bits don't match
        bool match = ((sha_dk0[0] ^ state[0]) == expected_digest[0]);
        if (match) {
            #pragma unroll
            for (int i = 1; i < 8; i++) {
                if ((sha_dk0[i] ^ state[i]) != expected_digest[i]) {
                    match = false;
                    break;
                }
            }
        }

        if (match) {
            if (atomicCAS(found_flag, 0, 1) == 0) {
                #pragma unroll
                for (int i = 0; i < 32; i++)
                    found_passcode[i] = passcode[i];
            }
            return;
        }
    } 
}


static inline uint32_t h_rotr(uint32_t x, int n) {
    return (x >> n) | (x << (32 - n));
}

static void sha256_transform_host(uint32_t state[8], const uint32_t block[16]) {
    uint32_t W[16];
    for (int i = 0; i < 16; i++) W[i] = block[i];

    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t e = state[4], f = state[5], g = state[6], h = state[7];

    for (int i = 0; i < 64; i++) {
        uint32_t w;
        if (i < 16) {
            w = W[i];
        } else {
            uint32_t s0 = h_rotr(W[(i-15)&15], 7) ^ h_rotr(W[(i-15)&15], 18) ^ (W[(i-15)&15] >> 3);
            uint32_t s1 = h_rotr(W[(i- 2)&15],17) ^ h_rotr(W[(i- 2)&15], 19) ^ (W[(i- 2)&15] >>10);
            w = s1 + W[(i-7)&15] + s0 + W[(i-16)&15];
            W[i & 15] = w;
        }

        uint32_t S1 = h_rotr(e, 6) ^ h_rotr(e, 11) ^ h_rotr(e, 25);
        uint32_t T1 = h + S1 + ((e & f) ^ (~e & g)) + h_K[i] + w;
        uint32_t S0 = h_rotr(a, 2) ^ h_rotr(a, 13) ^ h_rotr(a, 22);
        uint32_t T2 = S0 + ((a & b) ^ (a & c) ^ (b & c));
        h = g; g = f; f = e; e = d + T1;
        d = c; c = b; b = a; a = T1 + T2;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

static void sha256_host(const uint8_t* data, size_t len, uint8_t hash[32]) {
    uint32_t state[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };

    size_t offset = 0;
    while (offset + 64 <= len) {
        uint32_t block[16];
        for (int i = 0; i < 16; i++) {
            block[i] = ((uint32_t)data[offset + i*4    ] << 24)
                     | ((uint32_t)data[offset + i*4 + 1] << 16)
                     | ((uint32_t)data[offset + i*4 + 2] <<  8)
                     | ((uint32_t)data[offset + i*4 + 3]);
        }
        sha256_transform_host(state, block);
        offset += 64;
    }

    uint8_t padded[128];
    memset(padded, 0, sizeof(padded));
    size_t remaining = len - offset;
    memcpy(padded, data + offset, remaining);
    padded[remaining] = 0x80;

    int total_pad;
    if (remaining + 1 <= 56)
        total_pad = 64;
    else
        total_pad = 128;

    uint64_t bit_len = (uint64_t)len * 8;
    padded[total_pad - 8] = (uint8_t)(bit_len >> 56);
    padded[total_pad - 7] = (uint8_t)(bit_len >> 48);
    padded[total_pad - 6] = (uint8_t)(bit_len >> 40);
    padded[total_pad - 5] = (uint8_t)(bit_len >> 32);
    padded[total_pad - 4] = (uint8_t)(bit_len >> 24);
    padded[total_pad - 3] = (uint8_t)(bit_len >> 16);
    padded[total_pad - 2] = (uint8_t)(bit_len >>  8);
    padded[total_pad - 1] = (uint8_t)(bit_len);

    for (int b = 0; b < total_pad; b += 64) {
        uint32_t block[16];
        for (int i = 0; i < 16; i++) {
            block[i] = ((uint32_t)padded[b + i*4    ] << 24)
                     | ((uint32_t)padded[b + i*4 + 1] << 16)
                     | ((uint32_t)padded[b + i*4 + 2] <<  8)
                     | ((uint32_t)padded[b + i*4 + 3]);
        }
        sha256_transform_host(state, block);
    }

    for (int i = 0; i < 8; i++) {
        hash[i*4    ] = (uint8_t)(state[i] >> 24);
        hash[i*4 + 1] = (uint8_t)(state[i] >> 16);
        hash[i*4 + 2] = (uint8_t)(state[i] >>  8);
        hash[i*4 + 3] = (uint8_t)(state[i]);
    }
}


bool gpu_available() {
    int count = 0;
    cudaError_t err = cudaGetDeviceCount(&count);
    return (err == cudaSuccess && count > 0);
}

int gpu_device_count() {
    int count = 0;
    cudaError_t err = cudaGetDeviceCount(&count);
    return (err == cudaSuccess) ? count : 0;
}

std::string gpu_device_name(int device_id) {
    cudaDeviceProp prop;
    if (cudaGetDeviceProperties(&prop, device_id) != cudaSuccess) return "Unknown";
    return std::string(prop.name);
}


// faster code
bool check_passcode(const PkgCryptoData& data, const char* passcode) {
    uint8_t index_bytes[4] = {0, 0, 0, 0};
    uint8_t sha_index[32];
    sha256_host(index_bytes, 4, sha_index);

    uint8_t cid_padded[48];
    memset(cid_padded, 0, 48);
    size_t cid_len = strlen(data.content_id);
    if (cid_len > 48) cid_len = 48;
    memcpy(cid_padded, data.content_id, cid_len);
    uint8_t sha_cid[32];
    sha256_host(cid_padded, 48, sha_cid);

    uint8_t msg[96];
    memcpy(msg,      sha_index,  32);
    memcpy(msg + 32, sha_cid,    32);
    memcpy(msg + 64, passcode,   32);

    uint8_t dk0[32];
    sha256_host(msg, 96, dk0);

    // digest = SHA256(dk0) XOR dk0
    uint8_t sha_dk0[32];
    sha256_host(dk0, 32, sha_dk0);

    for (int i = 0; i < 32; i++)
        sha_dk0[i] ^= dk0[i];

    return memcmp(sha_dk0, data.expected_digest, 32) == 0;
}


static void gpu_worker(
    int device_id,
    const uint32_t* midstate,
    const uint32_t* expected,
    std::atomic<bool>& passcode_found,
    bool silence_mode,
    int batch_size_log2,
    std::string& out_result,
    std::mutex& output_mutex,
    std::atomic<uint64_t>& global_attempts)
{
    cudaError_t err = cudaSetDevice(device_id);
    if (err != cudaSuccess) {
        std::lock_guard<std::mutex> lock(output_mutex);
        std::cerr << "[-] GPU " << device_id << ": cudaSetDevice failed: "
                  << cudaGetErrorString(err) << std::endl;
        return;
    }

    // --- Auto-tuner state ---
    int current_log2 = batch_size_log2;
    const int threads_per_block = 256;

    // --- Device memory (read-only constants) ---
    uint32_t *d_midstate = nullptr, *d_expected = nullptr;

    // --- Zero-copy mapped memory (no cudaMemcpy needed to read results) ---
    int     *h_found_flag     = nullptr;   // host-side pinned pointer
    uint8_t *h_found_passcode = nullptr;   // host-side pinned pointer
    int     *d_found_flag     = nullptr;   // device-accessible pointer (mapped)
    uint8_t *d_found_passcode = nullptr;   // device-accessible pointer (mapped)

    // --- CUDA stream + events for async execution & timing ---
    cudaStream_t stream  = nullptr;
    cudaEvent_t ev_start = nullptr, ev_stop = nullptr;

    auto check = [&](cudaError_t e, const char* file, int line) -> bool {
        if (e != cudaSuccess) {
            std::lock_guard<std::mutex> lock(output_mutex);
            std::cerr << "[-] GPU " << device_id << " CUDA error: "
                      << cudaGetErrorString(e) << " (" << file << ":" << line << ")" << std::endl;
            return false;
        }
        return true;
    };
    #define GPU_CHECK(call) if (!check((call), __FILE__, __LINE__)) goto cleanup

    // Allocate device memory for constants
    GPU_CHECK(cudaMalloc(&d_midstate, 8 * sizeof(uint32_t)));
    GPU_CHECK(cudaMalloc(&d_expected, 8 * sizeof(uint32_t)));

    GPU_CHECK(cudaMemcpy(d_midstate, midstate, 8 * sizeof(uint32_t), cudaMemcpyHostToDevice));
    GPU_CHECK(cudaMemcpy(d_expected, expected, 8 * sizeof(uint32_t), cudaMemcpyHostToDevice));

    // Allocate zero-copy (mapped) pinned memory for results
    GPU_CHECK(cudaHostAlloc(&h_found_flag,     sizeof(int), cudaHostAllocMapped));
    GPU_CHECK(cudaHostAlloc(&h_found_passcode, 32,          cudaHostAllocMapped));
    *h_found_flag = 0;
    memset(h_found_passcode, 0, 32);

    GPU_CHECK(cudaHostGetDevicePointer(&d_found_flag,     h_found_flag,     0));
    GPU_CHECK(cudaHostGetDevicePointer(&d_found_passcode, h_found_passcode, 0));

    // Create stream and timing events
    GPU_CHECK(cudaStreamCreate(&stream));
    GPU_CHECK(cudaEventCreate(&ev_start));
    GPU_CHECK(cudaEventCreate(&ev_stop));

    {
        std::random_device rd;
        std::mt19937_64 host_rng(rd() ^ ((uint64_t)device_id << 32));

        // Print initial batch size for this GPU
        {
            std::lock_guard<std::mutex> lock(output_mutex);
            std::cout << "[+] GPU " << device_id << ": starting with batch 2^"
                      << current_log2 << " (" << (1 << current_log2)
                      << " threads x " << HASHES_PER_THREAD << " hashes/thread)" << std::endl;
        }

        while (!passcode_found.load(std::memory_order_relaxed)) {
            const int batch_size = 1 << current_log2;
            const int num_blocks = batch_size / threads_per_block;
            uint64_t base_seed   = host_rng();

            // Time the kernel for auto-tuning
            GPU_CHECK(cudaEventRecord(ev_start, stream));

            check_passcodes_kernel<<<num_blocks, threads_per_block, 0, stream>>>(
                d_midstate, d_expected, base_seed, d_found_flag, d_found_passcode);

            GPU_CHECK(cudaEventRecord(ev_stop, stream));
            GPU_CHECK(cudaEventSynchronize(ev_stop));

            // Each thread does HASHES_PER_THREAD passcodes
            global_attempts.fetch_add(
                (uint64_t)batch_size * HASHES_PER_THREAD, std::memory_order_relaxed);

            // --- Auto-tuner: adjust batch size based on kernel timing ---
            float kernel_ms = 0.0f;
            GPU_CHECK(cudaEventElapsedTime(&kernel_ms, ev_start, ev_stop));

            if (kernel_ms < AUTOTUNE_TARGET_MS_LOW && current_log2 < AUTOTUNE_MAX_LOG2) {
                current_log2++;
            } else if (kernel_ms > AUTOTUNE_TARGET_MS_HIGH && current_log2 > AUTOTUNE_MIN_LOG2) {
                current_log2--;
            }

            // --- Check for match via zero-copy (no cudaMemcpy!) ---
            if (*h_found_flag) {
                {
                    std::lock_guard<std::mutex> lock(output_mutex);
                    out_result = std::string(reinterpret_cast<char*>(h_found_passcode), 32);
                }
                passcode_found.store(true, std::memory_order_release);
                break;
            }
        }
    }

cleanup:
    if (ev_stop)           cudaEventDestroy(ev_stop);
    if (ev_start)          cudaEventDestroy(ev_start);
    if (stream)            cudaStreamDestroy(stream);
    if (d_midstate)        cudaFree(d_midstate);
    if (d_expected)        cudaFree(d_expected);
    if (h_found_flag)      cudaFreeHost(h_found_flag);
    if (h_found_passcode)  cudaFreeHost(h_found_passcode);
    #undef GPU_CHECK
}

std::string gpu_brute_force(
    const PkgCryptoData& data,
    std::atomic<bool>& passcode_found,
    bool silence_mode,
    int batch_size_log2)
{
    int device_count = gpu_device_count();
    if (device_count <= 0) return "";

    // Precompute midstate and expected digest on the host (shared by all GPUs)
    uint8_t index_bytes[4] = {0, 0, 0, 0};
    uint8_t sha_index[32];
    sha256_host(index_bytes, 4, sha_index);

    uint8_t cid_padded[48];
    memset(cid_padded, 0, 48);
    size_t cid_len = strlen(data.content_id);
    if (cid_len > 48) cid_len = 48;
    memcpy(cid_padded, data.content_id, cid_len);
    uint8_t sha_cid[32];
    sha256_host(cid_padded, 48, sha_cid);

    uint8_t first_block[64];
    memcpy(first_block,      sha_index, 32);
    memcpy(first_block + 32, sha_cid,   32);

    uint32_t midstate[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };
    {
        uint32_t block_words[16];
        for (int i = 0; i < 16; i++) {
            block_words[i] = ((uint32_t)first_block[i*4    ] << 24)
                           | ((uint32_t)first_block[i*4 + 1] << 16)
                           | ((uint32_t)first_block[i*4 + 2] <<  8)
                           | ((uint32_t)first_block[i*4 + 3]);
        }
        sha256_transform_host(midstate, block_words);
    }

    uint32_t expected[8];
    for (int i = 0; i < 8; i++) {
        expected[i] = ((uint32_t)data.expected_digest[i*4    ] << 24)
                    | ((uint32_t)data.expected_digest[i*4 + 1] << 16)
                    | ((uint32_t)data.expected_digest[i*4 + 2] <<  8)
                    | ((uint32_t)data.expected_digest[i*4 + 3]);
    }

    std::mutex output_mutex;
    std::atomic<uint64_t> global_attempts{0};
    std::string result;

    // Launch one thread per GPU
    std::vector<std::thread> workers;
    workers.reserve(device_count);
    for (int dev = 0; dev < device_count; dev++) {
        workers.emplace_back(
            gpu_worker, dev, midstate, expected,
            std::ref(passcode_found), silence_mode, batch_size_log2,
            std::ref(result), std::ref(output_mutex), std::ref(global_attempts));
    }

    auto start_time = std::chrono::steady_clock::now();
    while (!passcode_found.load(std::memory_order_relaxed)) {
        std::this_thread::sleep_for(std::chrono::seconds(2));
        if (passcode_found.load(std::memory_order_relaxed)) break;

        if (!silence_mode) {
            uint64_t total = global_attempts.load(std::memory_order_relaxed);
            auto now     = std::chrono::steady_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - start_time).count();
            double rate  = (elapsed > 0) ? (double)total / (double)elapsed : 0.0;

            auto hours   = elapsed / 3600;
            auto minutes = (elapsed % 3600) / 60;
            auto seconds = elapsed % 60;

            std::cout << "[GPU x" << device_count << "] ["
                      << std::setw(2) << std::setfill('0') << hours   << "h "
                      << std::setw(2) << std::setfill('0') << minutes << "m "
                      << std::setw(2) << std::setfill('0') << seconds << "s] | "
                      << std::fixed << std::setprecision(2) << (rate / 1e6) << " M/s | "
                      << total << " total attempts" << std::endl;
        }
    }

    for (auto& t : workers) t.join();
    return result;
}
