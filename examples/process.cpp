#include <Windows.h>

#include "omni/process.hpp"

#include <algorithm>
#include <filesystem>
#include <print>
#include <ranges>
#include <string>

namespace {

  [[nodiscard]] std::string process_name(const omni::process& process) {
    return process.name().empty() ? std::string{"<unnamed>"} : std::filesystem::path{process.name()}.string();
  }

} // namespace

int main() {
  auto snapshot = omni::processes::snapshot();
  if (!snapshot) {
    std::println("Failed to enumerate processes: {}", snapshot.error().message());
    return 1;
  }

  std::println("A process snapshot becomes a normal forward range:");
  for (const auto& process : *snapshot | std::views::take(10)) {
    std::println("  PID {:>6} parent={:>6} threads={:>3} name={}",
      process.id(),
      process.parent_id(),
      process.thread_count(),
      process_name(process));
  }

  auto current_process =
    std::ranges::find_if(*snapshot, [](const omni::process& process) { return process.id() == ::GetCurrentProcessId(); });
  if (current_process == snapshot->end()) {
    std::println("Current process was not found.");
    return 1;
  }

  std::println();
  std::println("A process entry can open its native handle:");
  auto handle = (*current_process).open_handle();
  if (!handle) {
    std::println("  failed to open handle: {}", handle.error().message());
    return 1;
  }

  std::println("  process id           : {}", (*current_process).id());
  std::println("  handle valid         : {}", handle->valid());
}
