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
#include <thread>
#include <vector>
#include <atomic>
#include <future>
#include <algorithm>
#include <stdexcept>
#include <memory>
#include <system_error>

std::atomic<bool> passcode_found(false);
std::string found_passcode;
std::string last_used_passcode;
std::string package_name;
std::string package_cid;
std::mutex output_mutex;
bool silence_mode = false;
volatile std::sig_atomic_t g_signal_received = false;
std::chrono::steady_clock::time_point global_start_time;


const std::string ascii_art = R"(
           __  ___  ___          __     ___          ___ 
|  |  /\  /__`  |  |__     |  | |__)     |  |  |\/| |__  
|/\| /~~\ .__/  |  |___    \__/ |  \     |  |  |  | |___ 
)";

struct ProcessResult
{
    std::string output = "";
    int returnCode = -1;
};


ProcessResult ExecuteCommand(const std::string& command) {
    ProcessResult result;

    SECURITY_ATTRIBUTES saAttr = {};
    saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
    saAttr.bInheritHandle = TRUE;
    saAttr.lpSecurityDescriptor = nullptr;

    HANDLE g_hChildStd_OUT_Rd = nullptr, g_hChildStd_OUT_Wr = nullptr;
    HANDLE g_hChildStd_ERR_Rd = nullptr, g_hChildStd_ERR_Wr = nullptr;

    try {
        if (!CreatePipe(&g_hChildStd_OUT_Rd, &g_hChildStd_OUT_Wr, &saAttr, 0))
        {
            throw std::runtime_error("Stdout pipe creation failed.");
        }
        if (!SetHandleInformation(g_hChildStd_OUT_Rd, HANDLE_FLAG_INHERIT, 0))
        {
            CloseHandle(g_hChildStd_OUT_Rd);
            CloseHandle(g_hChildStd_OUT_Wr);
            throw std::runtime_error("Stdout SetHandleInformation failed.");
        }

        if (!CreatePipe(&g_hChildStd_ERR_Rd, &g_hChildStd_ERR_Wr, &saAttr, 0))
        {
            CloseHandle(g_hChildStd_OUT_Rd);
            CloseHandle(g_hChildStd_OUT_Wr);
            throw std::runtime_error("Stderr pipe creation failed.");
        }

        if (!SetHandleInformation(g_hChildStd_ERR_Rd, HANDLE_FLAG_INHERIT, 0))
        {
            CloseHandle(g_hChildStd_OUT_Rd);
            CloseHandle(g_hChildStd_OUT_Wr);
            CloseHandle(g_hChildStd_ERR_Rd);

            throw std::runtime_error("Stderr SetHandleInformation failed.");
        }


        STARTUPINFOA si = {};
        si.cb = sizeof(STARTUPINFOA);
        si.hStdError = g_hChildStd_ERR_Wr;
        si.hStdOutput = g_hChildStd_OUT_Wr;
        si.dwFlags |= STARTF_USESTDHANDLES;

        PROCESS_INFORMATION pi = {};
        std::vector<char> commandLine(command.begin(), command.end());
        commandLine.push_back('\0');

        if (!CreateProcessA(nullptr, commandLine.data(), nullptr, nullptr, TRUE, 0, nullptr, nullptr, &si, &pi))
        {
            CloseHandle(g_hChildStd_OUT_Rd); CloseHandle(g_hChildStd_OUT_Wr);
            CloseHandle(g_hChildStd_ERR_Rd); CloseHandle(g_hChildStd_ERR_Wr);
            throw std::runtime_error("CreateProcessA failed with error code: " + std::to_string(GetLastError()));
        }

        CloseHandle(g_hChildStd_OUT_Wr);
        CloseHandle(g_hChildStd_ERR_Wr);

        DWORD dwRead;
        const int bufferSize = 4096;
        std::vector<char> buffer(bufferSize);
        std::string output;

        bool bSuccess = TRUE;
        while (bSuccess) {
            bSuccess = ReadFile(g_hChildStd_OUT_Rd, buffer.data(), bufferSize, &dwRead, nullptr);
            if (!bSuccess || dwRead == 0)
                break;
            output.append(buffer.begin(), buffer.begin() + dwRead);
        }

        CloseHandle(g_hChildStd_OUT_Rd);

        bSuccess = TRUE;
        while (bSuccess) {
            bSuccess = ReadFile(g_hChildStd_ERR_Rd, buffer.data(), bufferSize, &dwRead, nullptr);
            if (!bSuccess || dwRead == 0)
                break;
            output.append(buffer.begin(), buffer.begin() + dwRead);
        }
        CloseHandle(g_hChildStd_ERR_Rd);

        WaitForSingleObject(pi.hProcess, INFINITE);
        GetExitCodeProcess(pi.hProcess, (LPDWORD)&result.returnCode);

        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);

        result.output = output;

    }
    catch (const std::exception& e)
    {
        if (g_hChildStd_OUT_Rd) { CloseHandle(g_hChildStd_OUT_Rd); }
        if (g_hChildStd_OUT_Wr) { CloseHandle(g_hChildStd_OUT_Wr); }
        if (g_hChildStd_ERR_Rd) { CloseHandle(g_hChildStd_ERR_Rd); }
        if (g_hChildStd_ERR_Wr) { CloseHandle(g_hChildStd_ERR_Wr); }
        throw;
    }


    return result;
}



std::string generate_random_passcode(std::mt19937& gen, int length = 32) {

    const std::string characters = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_";
    std::string passcode(length, ' ');
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

void brute_force_passcode_thread(const std::string& input_file, const std::string& output_directory,
    const std::string& command_prefix, bool is_ps5, std::mt19937 gen) {

    while (!passcode_found) {
        std::string passcode = generate_random_passcode(gen);
        last_used_passcode = passcode;
        std::string Sc0Path = output_directory + "/Sc0";
        std::string Image0Path = output_directory + "/Image0";
        std::string full_command = command_prefix + passcode + " \"" + input_file + "\" \"" + output_directory + "\"";

        ProcessResult result;
        try {
            result = ExecuteCommand(full_command);
        }
        catch (const std::exception& e) {
            continue;
        }

        if (!silence_mode) {
            auto now = std::chrono::steady_clock::now();
            auto elapsed_seconds = std::chrono::duration_cast<std::chrono::seconds>(now - global_start_time).count();
            auto hours = elapsed_seconds / 3600;
            auto minutes = (elapsed_seconds % 3600) / 60;
            auto seconds = elapsed_seconds % 60;

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

        if (result.returnCode == 0 && std::filesystem::exists(Sc0Path) && std::filesystem::exists(Image0Path)) {
            passcode_found = true;
            found_passcode = passcode;
            break;
        }
    }
}

void brute_force_passcode(const std::string& input_file, const std::string& output_directory, int num_threads) {
    ensure_output_directory(output_directory);

    global_start_time = std::chrono::steady_clock::now();

    const char ps4_header_magic[] = { 0x7F, 0x43, 0x4E, 0x54 };
    const char ps5_header_magic[] = { 0x7F, 0x46, 0x49, 0x48 };
    char header[4];
    std::ifstream file(input_file, std::ios::binary);
    if (!file.read(header, sizeof(header))) {
        std::cerr << "[-] Error reading from the file." << std::endl;
        return;
    }
    file.close();

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

    std::random_device rd;
    std::vector<std::thread> threads;

    if (num_threads == 0)
        num_threads = std::thread::hardware_concurrency();
    if (num_threads == 0)
        num_threads = 4;

    std::cout << "[+] Running with " << num_threads << " threads" << std::endl;

    for (int i = 0; i < num_threads; ++i) {
        std::mt19937 gen(rd());
        threads.emplace_back(brute_force_passcode_thread, input_file, output_directory, command, is_ps5, gen);
    }

    for (auto& thread : threads) {
        thread.join();
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

    int num_threads = 0;
    if (argc < 3 || argc > 6) {
        std::cerr << "\nUsage: " << argv[0] << " <package> <output> [--silence] [-t <threads>]\n"
            << "<package> - The package file to brute force.\n"
            << "<output> - Output directory.\n"
            << "--silence - Activates 'Silence Mode' for minimal output.\n"
            << "-t <threads> - Sets the number of threads (Default: hardware concurrency or 4 if none).\n";
        return 1;
    }

    std::system("cls");
    std::cout << ascii_art << std::endl;

    for (int i = 3; i < argc; ++i) {
        if (std::string(argv[i]) == "--silence") {
            silence_mode = true;
        }
        else if (std::string(argv[i]) == "-t" && i + 1 < argc) {
            try {
                num_threads = std::stoi(argv[i + 1]);
                if (num_threads < 0) {
                    std::cerr << "[-] Invalid thread count: Must be a non-negative number." << std::endl;
                    return 1;
                }
                i++;
            }
            catch (const std::invalid_argument& e) {
                std::cerr << "[-] Invalid thread count: Not a valid number." << std::endl;
                return 1;
            }
            catch (const std::out_of_range& e) {
                std::cerr << "[-] Invalid thread count: Number too large." << std::endl;
                return 1;
            }
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

    brute_force_passcode(package_name, output, num_threads);

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
