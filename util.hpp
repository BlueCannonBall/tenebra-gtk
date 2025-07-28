#pragma once

#include <filesystem>
#include <string>
#ifdef _WIN32
    #include <stdint.h>
#endif

// Bridged
#ifdef _WIN32
typedef int64_t pid_t;
#endif

std::filesystem::path get_config_path();
pid_t get_tenebra_pid();
std::string get_common_name_from_cert(const char* cert_path);
