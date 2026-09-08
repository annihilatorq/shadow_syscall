#include <Windows.h>

#include "omni/process.hpp"

#include <algorithm>
#include <print>
#include <ranges>
#include <string>

namespace {

  [[nodiscard]] std::string to_utf8(std::wstring_view wide) {
    if (wide.empty()) {
      return {};
    }
    const int size =
      ::WideCharToMultiByte(CP_UTF8, 0, wide.data(), static_cast<int>(wide.size()), nullptr, 0, nullptr, nullptr);
    std::string narrow(static_cast<std::size_t>(size), '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, wide.data(), static_cast<int>(wide.size()), narrow.data(), size, nullptr, nullptr);
    return narrow;
  }

  [[nodiscard]] std::string process_name(const omni::process& process) {
    return process.name().empty() ? "<unnamed>" : to_utf8(process.name());
  }

  [[nodiscard]] auto by_id(std::uint32_t id) {
    return [id](const omni::process& process) {
      return process.id() == id;
    };
  }

} // namespace

int main() {
  ::SetConsoleOutputCP(CP_UTF8);

  auto snapshot = omni::processes::snapshot();
  if (!snapshot) {
    std::println("Failed to enumerate processes: {}", snapshot.error().message());
    return 1;
  }

  std::println("First 10 entries of the snapshot:");
  for (const omni::process process : *snapshot | std::views::take(10)) {
    std::println("  pid {:>6}  parent {:>6}  threads {:>3}  {}",
      process.id(),
      process.parent_id(),
      process.thread_count(),
      process_name(process));
  }

  auto current_process = std::ranges::find_if(*snapshot, by_id(::GetCurrentProcessId()));
  if (current_process == snapshot->end()) {
    std::println("Current process was not found.");
    return 1;
  }

  // omni::process is a view type that is cheap to copy
  const omni::process self = *current_process;

  const auto parent_it = std::ranges::find_if(*snapshot, by_id(self.parent_id()));
  std::println();
  std::println("Current process: {} (pid {})", process_name(self), self.id());
  std::println("Parent:          {}", parent_it == snapshot->end() ? std::string{"<exited>"} : process_name(*parent_it));

  auto handle = self.open_handle();
  if (!handle) {
    std::println("open_handle failed: {}", handle.error().message());
    return 1;
  }
  std::println("Opened own handle: {}", ::GetProcessId(handle->get()) == self.id());

  const auto system_it = std::ranges::find_if(*snapshot, by_id(4));
  if (system_it != snapshot->end()) {
    const auto system_handle = system_it->open_handle(omni::process_access::all_access);
    if (!system_handle && system_handle.error() == std::errc::permission_denied) {
      std::println("System (pid 4) with all_access: permission denied, as expected without SeDebugPrivilege");
    }
  }
}
