#include "util.hpp"
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <stdio.h>
#ifdef _WIN32
// clang-format off
    #include <windows.h>
    #include <tlhelp32.h>
// clang-format on
#else
    #include <stdlib.h>
    #include <sys/wait.h>
    #include <unistd.h>
    #ifdef __linux__
        #include <algorithm>
        #include <ctype.h>
        #include <fstream>
    #else
        #include <sys/sysctl.h>
        #include <sys/types.h>
        #include <vector>
    #endif
#endif

std::filesystem::path get_config_path() {
    std::filesystem::path ret;
#ifdef _WIN32
    ret = "C:\\tenebra";
#elif defined(__APPLE__)
    if (char* home = getenv("HOME")) {
        ret = std::filesystem::path(home) / "Library" / "Application Support" / "tenebra";
    }
#else
    if (char* xdg_config_home = getenv("XDG_CONFIG_HOME")) {
        ret = std::filesystem::path(xdg_config_home) / "tenebra";
    } else if (char* home = getenv("HOME")) {
        ret = std::filesystem::path(home) / ".config" / "tenebra";
    }
#endif
    return ret;
}

pid_t get_tenebra_pid() {
#ifdef _WIN32
    HANDLE snapshot;
    if ((snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)) == INVALID_HANDLE_VALUE) {
        return -1;
    }

    PROCESSENTRY32 entry = {.dwSize = sizeof(PROCESSENTRY32)};
    if (!Process32First(snapshot, &entry)) {
        CloseHandle(snapshot);
        return -1;
    }
    do {
        if (entry.th32ProcessID == GetCurrentProcessId()) {
            continue;
        }

        if (_strcmpi(entry.szExeFile, "tenebra.exe") == 0) {
            CloseHandle(snapshot);
            return entry.th32ProcessID;
        }
    } while (Process32Next(snapshot, &entry));

    CloseHandle(snapshot);
    return -1;
#elif defined(__linux__)
    for (const auto& entry : std::filesystem::directory_iterator("/proc")) {
        if (entry.is_directory()) {
            std::filesystem::path path = entry.path();
            std::string filename = path.filename();
            if (std::all_of(filename.begin(), filename.end(), [](char c) -> bool {
                    return isdigit((unsigned char) c);
                })) {
                pid_t pid;
                if ((pid = std::stoi(filename)) == getpid()) {
                    continue;
                }

                std::ifstream status_file(path / "status");
                if (status_file.is_open()) {
                    bool uid_matches = false;
                    for (std::string line; std::getline(status_file, line);) {
                        if (!line.rfind("Uid:", 0)) {
                            uid_matches = std::stoul(line.substr(5)) == getuid();
                            break;
                        }
                    }
                    if (!uid_matches) continue;
                }

                std::ifstream comm_file(path / "comm");
                if (comm_file.is_open()) {
                    std::string comm;
                    if (std::getline(comm_file, comm) && comm == "tenebra") {
                        return pid;
                    }
                }
            }
        }
    }
#else
    size_t size;
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_UID, (int) getuid()};
    if (sysctl(mib, 4, nullptr, &size, nullptr, 0) == -1) {
        return -1;
    }

    std::vector<struct kinfo_proc> processes(size / sizeof(struct kinfo_proc));
    if (sysctl(mib, 4, processes.data(), &size, nullptr, 0) == -1) {
        return -1;
    }

    for (const auto& process : processes) {
        if (process.kp_proc.p_pid != getpid() && !strcmp(process.kp_proc.p_comm, "tenebra")) {
            return process.kp_proc.p_pid;
        }
    }
#endif
    return -1;
}

std::string get_common_name_from_cert(const char* cert_path) {
    std::string ret = "localhost";
    if (FILE* fp = fopen(cert_path, "r")) {
        X509* cert = PEM_read_X509(fp, nullptr, nullptr, nullptr);
        fclose(fp);
        if (cert) {
            X509_NAME* subject_name = X509_get_subject_name(cert);
            if (int index = X509_NAME_get_index_by_NID(X509_get_subject_name(cert), NID_commonName, -1); index != -1) {
                ret = (const char*) ASN1_STRING_get0_data(X509_NAME_ENTRY_get_data(X509_NAME_get_entry(subject_name, index)));
            }
            X509_free(cert);
        }
    }
    return ret;
}
