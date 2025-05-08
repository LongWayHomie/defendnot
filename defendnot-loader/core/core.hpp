#pragma once
#include <string>
#include <string_view>

#include <Windows.h>

namespace loader {
    struct Config {
    public:
        std::string name;
        bool disable;
        bool verbose;
        bool from_autorun;
        bool manage_autorun;
    };

    [[nodiscard]] HANDLE inject(std::string_view dll_path, std::string_view proc_name);
    [[nodiscard]] bool add_to_autorun();
    [[nodiscard]] bool remove_from_autorun();
} // namespace loader
