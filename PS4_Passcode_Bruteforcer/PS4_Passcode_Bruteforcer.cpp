#include <iostream>
#include <iomanip>
#include <fstream>
#include <sstream>
#include <string>
#include <filesystem>
#include <chrono>
#include <csignal>
#include <Windows.h>
#include <random>
#include <mutex>

std::atomic<bool> passcode_found(false);
std::string found_passcode;
std::string last_used_passcode;
std::string package_name;
std::string package_cid;
std::mutex output_mutex;
bool debug_mode = false;
bool silence_mode = false;

volatile std::sig_atomic_t g_signal_received = false;

const std::string ascii_art = R"(
           __  ___  ___          __     ___          ___ 
|  |  /\  /__`  |  |__     |  | |__)     |  |  |\/| |__  
|/\| /~~\ .__/  |  |___    \__/ |  \     |  |  |  | |___ 
)";

std::string generate_random_passcode(int length = 32) {
    if (debug_mode) {
        return "00000000000000000000000000000000";
    }

    const std::string characters = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_";
    std::string passcode(length, ' ');

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> distribution(0, characters.size() - 1);

    for (int i = 0; i < length; ++i) {
        passcode[i] = characters[distribution(gen)];
    }

    return passcode;
}

void ensure_output_directory(const std::string& output_directory) {
    std::filesystem::create_directories(output_directory);
}

bool is_pkg_file(const std::string& file_name) {
    return file_name.size() >= 4 && file_name.substr(file_name.size() - 4) == ".pkg";
}

std::string read_cid(const std::string& package_file) {
    std::ifstream file(package_file, std::ios::binary);
    if (!file) {
        std::cerr << "[-] Failed to open the package file." << std::endl;
        return "";
    }

    file.seekg(0x40, std::ios::beg);

    char cid_buffer[36];
    file.read(cid_buffer, sizeof(cid_buffer));

    if (!file) {
        std::cerr << "[-] Failed to read the CID from the package file." << std::endl;
        return "";
    }

    std::string cid_string(cid_buffer, sizeof(cid_buffer));

    cid_string.erase(std::remove_if(cid_string.begin(), cid_string.end(),
        [](unsigned char c) { return !std::isprint(c); }), cid_string.end());

    return cid_string;
}

bool CheckExecutable(const std::string& executableName) {
    std::string path = ".";
    std::string fullPath = path + "\\" + executableName;

    std::filesystem::path fullPathObj = std::filesystem::absolute(fullPath);

    return std::filesystem::exists(fullPath);
}

void brute_force_passcode(const std::string& input_file, const std::string& output_directory) {
    ensure_output_directory(output_directory);

    auto start_time = std::chrono::steady_clock::now();

    const char ps4_header_magic[] = { 0x7F, 0x43, 0x4E, 0x54 };
    const char ps5_header_magic[] = { 0x7F, 0x46, 0x49, 0x48 };
    char header[4];
    std::ifstream file(input_file, std::ios::binary);

    if (!file.read(header, sizeof(header))) {
        std::cerr << "[-] Error reading from the file." << std::endl;
        return;
    }

    std::string command;
    bool is_ps5 = false;
    if (std::memcmp(header, ps4_header_magic, sizeof(ps4_header_magic)) == 0) {
        std::cout << "[+] Detected PS4 package file." << std::endl;
        if (!CheckExecutable("orbis-pub-cmd.exe")) {
            std::cerr << "[-] Required executable 'orbis-pub-cmd.exe' not found." << std::endl;
            return;
        }
        command = "orbis-pub-cmd.exe img_extract --passcode ";
        package_cid = read_cid(input_file);
    }
    else if (std::memcmp(header, ps5_header_magic, sizeof(ps5_header_magic)) == 0) {
        std::cout << "[+] Detected PS5 package file." << std::endl;
        if (!CheckExecutable("prospero-pub-cmd.exe")) {
            std::cerr << "[-] Required executable 'prospero-pub-cmd.exe' not found." << std::endl;
            return;
        }
        command = "prospero-pub-cmd.exe img_extract --passcode ";
        is_ps5 = true;
    }
    else {
        std::cerr << "[-] Invalid package file header." << std::endl;
        return;
    }

    while (!passcode_found) {
        std::string passcode = generate_random_passcode();
        last_used_passcode = passcode;
        std::string Sc0Path = output_directory + "/Sc0";
        std::string Image0Path = output_directory + "/Image0";

        std::string full_command = command + passcode + " \"" + input_file + "\" \"" + output_directory + "\"";

        try {
            int return_code;
            return_code = std::system((full_command + " > nul 2>&1").c_str());

            auto end_time = std::chrono::steady_clock::now();
            auto elapsed_seconds = std::chrono::duration_cast<std::chrono::seconds>(end_time - start_time).count();
            auto hours = elapsed_seconds / 3600;
            auto minutes = (elapsed_seconds % 3600) / 60;
            auto seconds = elapsed_seconds % 60;

            if (!silence_mode) {
                std::lock_guard<std::mutex> lock(output_mutex);
                std::cout << "[" << std::setw(2) << std::setfill('0') << hours << "h "
                    << std::setw(2) << std::setfill('0') << minutes << "m "
                    << std::setw(2) << std::setfill('0') << seconds << "s] | Passcode: " << passcode;
                if (!is_ps5) {
                    std::cout << " | " << package_cid;
                }
                else {
                    std::string filename_without_extension = std::filesystem::path(input_file).stem().string();
                    std::cout << " | " << filename_without_extension;
                }
                std::cout << std::endl;
            }

            if (return_code == 0 && std::filesystem::exists(Sc0Path) && std::filesystem::exists(Image0Path)) {
                passcode_found = true;
                found_passcode = passcode;
                break;
            }
        }
        catch (const std::exception& e) {
            // no? we never hit this because we cat lovers here!
        }
    }
}

void SignalHandler(int signal) {
    g_signal_received = true;
    if (!last_used_passcode.empty()) {
        std::cout << "[+] Last used passcode: " << last_used_passcode << std::endl;
    }
    std::cout << "[+] Exiting..." << std::endl;
    exit(signal);
}

int main(int argc, char* argv[]) {
    srand(static_cast<unsigned>(time(nullptr)));

    if (argc < 3 || argc > 4) {
        std::cerr << "\nUsage: " << argv[0] << " <package> <output> [--silence]\n"
            << "<package> - The package file to brute force.\n"
            << "<output> - Output directory.\n"
            << "--silence - Activates 'Silence Mode' for minimal output.\n";
        return 1;
    }

    std::system("cls");

    std::cout << ascii_art << std::endl;

    if (argc == 4) {
        if (std::string(argv[3]) == "--silence") {
            silence_mode = true;
        }
    }

    if (silence_mode) {
        std::cout << "[+] Silence Mode activated. This Window will be quiet..." << std::endl;
    }
    else {
        std::cout << "Made by hoppers - v1.08" << std::endl;
    }

    package_name = argv[1];
    std::string output = argv[2];

    if (!is_pkg_file(package_name)) {
        std::cerr << "[-] Invalid package file format." << std::endl;
        return 1;
    }

    std::string windowTitle = "Waste Ur Time is wasting ur time on " + package_name;
    SetConsoleTitleA(windowTitle.c_str());

    std::signal(SIGINT, SignalHandler);

    brute_force_passcode(package_name, output);

    if (passcode_found) {
        std::string successFileName = package_name + ".success";
        std::ofstream successFile(successFileName);
        if (successFile.is_open()) {
            successFile << found_passcode;
            successFile.close();
            std::cout << "[+] Passcode has been saved to: " << successFileName << std::endl;
        }
        else {
            std::cerr << "[-] Failed to create/save the success file." << std::endl;
        }

        std::cout << "[+] We did it! \n[+] Passcode: " << found_passcode << std::endl;
    }
    else {
        std::cout << "[-] Passcode not found." << std::endl;
    }

    return 0;
}