#include "core/core.hpp"
#include "shared/ctx.hpp"
#include "shared/defer.hpp"
#include "shared/ipc.hpp"
#include "shared/names.hpp"
#include <argparse/argparse.hpp>

#include <format>
#include <print>
#include <thread>

namespace {
    void setup_window(const loader::Config& config) {
        if (!config.from_autorun || config.verbose) {
            shared::alloc_console();
        }
    }

    void setup_context(const loader::Config& config) {
        std::println("[*] Setting up context");

        if (config.name.length() > shared::kMaxNameLength) {
            throw std::runtime_error(std::format("[!] Max name length is {} characters", shared::kMaxNameLength));
        }

        shared::ctx.state = config.disable ? shared::State::OFF : shared::State::ON;
        shared::ctx.verbose = config.verbose;
        std::ranges::copy(config.name, shared::ctx.name.data());

        /// No need to overwrite ctx if we are called from autorun
        if (!config.from_autorun) {
            std::println("[*] Overwriting ctx.bin");
            shared::ctx.serialize();
        }
    }

    [[nodiscard]] HANDLE load_defendnot() {
        std::println("[*] Loading DefendNot");

        auto dll_path = shared::get_this_module_path().parent_path();
        dll_path /= names::kDllName;
        if (!std::filesystem::exists(dll_path)) {
            throw std::runtime_error(std::format("[!] {} does not exist!", names::kDllName));
        }

        return loader::inject(dll_path.string(), names::kVictimProcess);
    }

    void wait_for_finish(shared::InterProcessCommunication& ipc) {
        std::println("[*] Waiting for process to finish. This can take a while...");
        std::cout << std::flush;
        while (!ipc->finished) {
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }
        std::println("[+] Success! {}", ipc->success);
    }

    void process_autorun(const loader::Config& config) {
        if (shared::ctx.state == shared::State::ON) {
            std::println("[*] Added to Autorun: {}", loader::add_to_autorun());
        } else {
            std::println("[*] Removed from Autorun: {}", loader::remove_from_autorun());
        }
    }

    void banner(const loader::Config& config) {
        std::println();
        std::println("[*] Thanks for using {}", names::kProjectName);
        std::println("[*] Please don't forget to leave a star at {}", names::kRepoUrl);

        if (!config.from_autorun) {
            system("pause");
        }
    }
} // namespace

int main(int argc, char* argv[]) try {
    argparse::ArgumentParser program(std::format("{}-loader", names::kProjectName), "1.1.0");

    program.add_argument("-n", "--name").help("AV display name").default_value(std::string(names::kRepoUrl)).nargs(1);
    program.add_argument("-d", "--disable").help(std::format("Disable {}", names::kProjectName)).default_value(false).implicit_value(true);
    program.add_argument("-v", "--verbose").help("Verbose logging").default_value(false).implicit_value(true);
    program.add_argument("--from-autorun").hidden().default_value(false).implicit_value(true);
    program.add_argument("--autorun").help("Add to or remove from autorun based on --disable flag").default_value(false).implicit_value(true);

    try {
        program.parse_args(argc, argv);
    } catch (...) {
        shared::alloc_console();
        std::cerr << program;
        system("pause");
        return EXIT_FAILURE;
    }

    auto config = loader::Config{
        .name = program.get<std::string>("-n"),
        .disable = program.get<bool>("-d"),
        .verbose = program.get<bool>("-v"),
        .from_autorun = program.get<bool>("--from-autorun"),
        .manage_autorun = program.get<bool>("--autorun")
    };

    setup_window(config);
    setup_context(config);

    /// \todo @es3n1n: move this to a separate function and add move ctor for ipc
    std::println("[*] Setting up IPC");
    auto ipc = shared::InterProcessCommunication(shared::InterProcessCommunicationMode::READ_WRITE, true);
    ipc->finished = false;

    const auto process = load_defendnot();
    defer->void {
        TerminateProcess(process, 0);
    };

    wait_for_finish(ipc);

    if (config.manage_autorun) {
        process_autorun(config);
    } else if (!config.from_autorun) {
        std::println("[*] Autorun option is disabled.");
    }
    banner(config);

    return EXIT_SUCCESS;
} catch (std::exception& err) {
    std::println(stderr, "[!] Fatal Error! {}", err.what());
    system("pause");
    return EXIT_FAILURE;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PSTR lpCmdLine, int nCmdShow) {
    return main(__argc, __argv);
}
