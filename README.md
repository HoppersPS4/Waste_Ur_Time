## Purpose

Welcome 'Waste_Ur_Time,' a program that takes on the seemingly impossible task of bruteforcing PS4 and PS5 Package Passcodes, where success is as elusive as Haytada loving piracy.

# Preview

![ezgif com-video-to-gif](https://github.com/HoppersPS4/Waste_Ur_Time/assets/80831610/214df483-16ec-47ba-bc77-0b695cad1843)

# Features
  - Able to Bruteforce (Added in v1.00) ✅
  - Auto Detect (PS4/PS5)
  - CUDA GPU Acceleration (PS4 PKGs) ✅
  - Multi-GPU support (automatically uses all available CUDA GPUs)
  - Auto-tuning batch sizes for optimal GPU performance
  - Multi-threaded CPU bruteforce with configurable thread count
  - RocksDB progress tracking (CPU mode) - stop and resume without losing progress
  - Silence Mode for minimal output
  - CMake & Visual Studio build support

# Usage

```
Waste_Ur_Time.exe <package> <output> [--silence] [--gpu] [-t <threads>]
```

| Argument | Description |
|----------|-------------|
| `<package>` | The package file to brute force |
| `<output>` | Output directory |
| `--silence` | Activates 'Silence Mode' for minimal output |
| `--gpu` | Use GPU acceleration (CUDA, PS4 PKGs only) |
| `-t <threads>` | Sets the number of threads (Default: hardware concurrency or 4) |

# Building

### Visual Studio
Open `PS4_Passcode_Bruteforcer.sln` and build. Requires CUDA Toolkit for GPU support.

### CMake
```
cmake -B build
cmake --build build
```
CUDA is auto-detected. If not found, builds in CPU-only mode.

# Requirements
  - `orbis-pub-cmd.exe` for PS4 packages
  - `prospero-pub-cmd.exe` for PS5 packages
  - NVIDIA GPU + CUDA Toolkit (for `--gpu` mode)
  - RocksDB (fetched automatically with CMake)

# Updates

GPU Support added by [@Pcniado](https://github.com/Pcniado)

02/09/2026
- Full CUDA GPU bruteforce (PS4 PKGs) - no more shelling out to orbis-pub-cmd for each attempt
- Multi-GPU support - spawns one worker thread per GPU

27/06/2024
- Made a few changes, added an Auto Detect feature for PS4/PS5 packages.

10/25/2023 - Source published

09/29/2023 - 1.07b Released
- alot of code cleaing for future source release
- PS5 Support
- A ton of checks to see if the Package file is actually a real Playstation Package.

09/24/2023 - 1.06 Released
- Removed 1.05 Build because i dont want to get sued.
- [Saved Passcode Support](https://github.com/HoppersPS4/Waste_Ur_Time/tree/main#ps4_passcodestxt--ps5_passcodestxt)

09/23/2023 - 1.05 Released
- removed

09/23/2023 - 1.04 Released
  - GPU Support added (use --GPU flag)
  - General Improvement to make the program more light and faster.
  - Added a somewhat database of Known Passcodes or already bruteforced Passcodes.

09/23/2023 - 1.03 Released
  - Recode, its now in C++!
  - This software update improves Bruteforce performance. ( ͡° ͜ʖ ͡°)

09/21/2023 - 1.02 Released
  - General Improvement
  - Changes Password Generation
    
09/20/2023 - 1.01 Released
  - Added Threads
  - Some Optimization
    
09/20/2023 - 1.00 Released
  - Inital Release

# Known Issues
- `--gpu` only supports PS4 PKG files for now. PS5 GPU support is not yet implemented.
- Linux support is experimental/stubbed - the extraction tools are Windows-only.
