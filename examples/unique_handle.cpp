#include "omni/handle.hpp"

#include <Windows.h>

#include <array>
#include <filesystem>
#include <print>
#include <string>
#include <utility>

namespace {

  [[nodiscard]] DWORD example_process_id() {
    HWND shell_window = ::GetShellWindow();
    if (shell_window != nullptr) {
      DWORD process_id{};
      ::GetWindowThreadProcessId(shell_window, &process_id);
      if (process_id != 0U) {
        return process_id;
      }
    }

    return ::GetCurrentProcessId();
  }

  [[nodiscard]] omni::unique_handle open_example_process() {
    return omni::unique_handle{::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, example_process_id())};
  }

  [[nodiscard]] std::wstring process_image_path(HANDLE handle) {
    if (handle == nullptr) {
      return {};
    }

    std::array<wchar_t, MAX_PATH> buffer{};
    auto length = static_cast<DWORD>(buffer.size());
    if (::QueryFullProcessImageNameW(handle, 0, buffer.data(), &length) == FALSE) {
      return {};
    }

    return {buffer.data(), length};
  }

} // namespace

int main() {
  omni::unique_handle process = open_example_process();
  if (!process) {
    std::println("Failed to open a process handle.");
    return 1;
  }

  const DWORD process_id = ::GetProcessId(process.get());
  const std::wstring image_path = process_image_path(process.get());
  const std::string image_path_string =
    image_path.empty() ? std::string{"<unknown>"} : std::filesystem::path{image_path}.string();

  std::println("unique_handle wraps a normal WinAPI process handle in RAII without changing how you use it:");
  std::println("  process id           : {}", process_id);
  std::println("  handle               : {:#x}", reinterpret_cast<std::uintptr_t>(process.get()));
  std::println("  image path           : {}", image_path_string);
  std::println("  valid                : {}", process.valid());

  std::println();

  std::println("The raw handle is always one call away:");
  DWORD exit_code{};
  ::GetExitCodeProcess(process.get(), &exit_code);
  std::println("  GetExitCodeProcess   : {}", exit_code);

  std::println();

  std::println("And HANDLE* output parameters become just as pleasant:");
  omni::unique_handle read_pipe;
  omni::unique_handle write_pipe;

  if (::CreatePipe(read_pipe.out_ptr(), write_pipe.out_ptr(), nullptr, 0U) == FALSE) {
    std::println("  CreatePipe failed.");
    return 1;
  }

  const std::string message = "omni";
  std::array<char, 16> buffer{};
  DWORD bytes_written{};
  DWORD bytes_read{};

  const BOOL write_ok =
    ::WriteFile(write_pipe.get(), message.data(), static_cast<DWORD>(message.size()), &bytes_written, nullptr);
  const BOOL read_ok = ::ReadFile(read_pipe.get(), buffer.data(), bytes_written, &bytes_read, nullptr);
  if (write_ok == FALSE || read_ok == FALSE) {
    std::println("  Pipe I/O failed.");
    return 1;
  }

  std::println("  read pipe handle     : {:#x}", reinterpret_cast<std::uintptr_t>(read_pipe.get()));
  std::println("  write pipe handle    : {:#x}", reinterpret_cast<std::uintptr_t>(write_pipe.get()));
  std::println("  transferred payload  : {}", std::string{buffer.data(), bytes_read});

  std::println();

  std::println("Ownership transfer stays explicit:");
  omni::unique_handle moved_process{std::move(process)};
  std::println("  source after move    : {}", static_cast<bool>(process));
  std::println("  destination pid      : {}", ::GetProcessId(static_cast<HANDLE>(moved_process.get())));

  std::println();

  std::println("And cleanup can stay just as explicit when you want it:");
  auto close_status = moved_process.close();
  std::println("  close() status       : 0x{:08X}", static_cast<std::uint32_t>(close_status.value));
  std::println("  close() success      : {}", close_status.is_success());
  std::println("  wrapper after close  : {}", static_cast<bool>(moved_process));

  return close_status.is_success() ? 0 : 1;
}
