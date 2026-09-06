#pragma once

#include <cstdint>

#include "omni/win/unicode_string.hpp"

namespace omni::win {

  // https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ex/sysinfo/process.htm
  struct system_process_information {
    std::uint32_t next_entry_offset;
    std::uint32_t number_of_threads;
    std::int64_t working_set_private_size;
    std::uint32_t hard_fault_count;
    std::uint32_t number_of_threads_high_watermark;
    std::uint64_t cycle_time;
    std::int64_t create_time;
    std::int64_t user_time;
    std::int64_t kernel_time;
    win::unicode_string image_name;
    std::int32_t base_priority;
    void* unique_process_id;
    void* inherited_from_unique_process_id;
    std::uint32_t handle_count;
    std::uint32_t session_id;
    std::uintptr_t unique_process_key;
    std::uintptr_t peak_virtual_size;
    std::uintptr_t virtual_size;
    std::uint32_t page_fault_count;
    std::uintptr_t peak_working_set_size;
    std::uintptr_t working_set_size;
    std::uintptr_t quota_peak_paged_pool_usage;
    std::uintptr_t quota_paged_pool_usage;
    std::uintptr_t quota_peak_non_paged_pool_usage;
    std::uintptr_t quota_non_paged_pool_usage;
    std::uintptr_t pagefile_usage;
    std::uintptr_t peak_pagefile_usage;
    std::uintptr_t private_page_count;
    std::int64_t read_operation_count;
    std::int64_t write_operation_count;
    std::int64_t other_operation_count;
    std::int64_t read_transfer_count;
    std::int64_t write_transfer_count;
    std::int64_t other_transfer_count;
  };

  static_assert(sizeof(system_process_information) == (sizeof(void*) == 8 ? 0x100 : 0xB8));
  static_assert(offsetof(system_process_information, image_name) == 0x38);
  static_assert(offsetof(system_process_information, unique_process_id) == (sizeof(void*) == 8 ? 0x50 : 0x44));
  static_assert(offsetof(system_process_information, read_operation_count) == (sizeof(void*) == 8 ? 0xD0 : 0x88));

} // namespace omni::win
