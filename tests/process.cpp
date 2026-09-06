#include <Windows.h>

#include "omni/process.hpp"
#include "test_utils.hpp"

ut::suite<"omni::processes"> process_suite = [] {
  "snapshot enumerates the current process"_test = [] {
    auto snapshot = omni::processes::snapshot();

    expect(fatal(snapshot.has_value()));

    bool found_current_process{};
    for (const omni::process& process : *snapshot) {
      if (process.id() == ::GetCurrentProcessId()) {
        found_current_process = true;
        expect(process.parent_id() != 0U);
        expect(process.thread_count() != 0U);
        expect(process.open_handle().has_value());
      }
    }

    expect(found_current_process);
  };
};
