#pragma once

#include <compare>
#include <cstdint>
#include <format>

namespace omni {

  enum class severity : std::uint8_t {
    success = 0,
    information = 1,
    warning = 2,
    error = 3,
  };

  enum class facility : std::uint16_t {
    debugger = 0x1,
    rpc_runtime = 0x2,
    rpc_stubs = 0x3,
    io_error_code = 0x4,
    codclass_error_code = 0x6,
    ntwin32 = 0x7,
    ntcert = 0x8,
    ntsspi = 0x9,
    terminal_server = 0xA,
    mui_error_code = 0xB,
    usb_error_code = 0x10,
    hid_error_code = 0x11,
    firewire_error_code = 0x12,
    cluster_error_code = 0x13,
    acpi_error_code = 0x14,
    sxs_error_code = 0x15,
    transaction = 0x19,
    commonlog = 0x1A,
    video = 0x1B,
    filter_manager = 0x1C,
    monitor = 0x1D,
    graphics_kernel = 0x1E,
    driver_framework = 0x20,
    fve_error_code = 0x21,
    fwp_error_code = 0x22,
    ndis_error_code = 0x23,
    tpm = 0x29,
    rtpm = 0x2A,
    hypervisor = 0x35,
    ipsec = 0x36,
    virtualization = 0x37,
    volmgr = 0x38,
    bcd_error_code = 0x39,
    win32k_ntuser = 0x3E,
    win32k_ntgdi = 0x3F,
    resume_key_filter = 0x40,
    rdbss = 0x41,
    bth_att = 0x42,
    secureboot = 0x43,
    audio_kernel = 0x44,
    vsm = 0x45,
    volsnap = 0x50,
    sdbus = 0x51,
    shared_vhdx = 0x5C,
    smb = 0x5D,
    interix = 0x99,
    spaces = 0xE7,
    security_core = 0xE8,
    system_integrity = 0xE9,
    licensing = 0xEA,
    platform_manifest = 0xEB,
    app_exec = 0xEC,
    maximum_value = 0xED,
  };

  struct status {
    using value_type = std::int32_t;

    value_type value{};

    status& operator=(std::int32_t val) noexcept {
      value = val;
      return *this;
    }

    [[nodiscard]] constexpr bool operator==(std::int32_t val) const noexcept {
      return value == val;
    }

    [[nodiscard]] constexpr bool operator==(status other) const noexcept {
      return value == other.value;
    }

    [[nodiscard]] constexpr auto operator<=>(const status& other) const noexcept = default;
    [[nodiscard]] constexpr std::strong_ordering operator<=>(std::int32_t val) const noexcept {
      return value <=> val;
    }

    [[nodiscard]] constexpr bool is_success() const noexcept {
      return value >= 0;
    }

    [[nodiscard]] constexpr bool is_information() const noexcept {
      return severity_bits() == static_cast<std::uint32_t>(omni::severity::information);
    }

    [[nodiscard]] constexpr bool is_warning() const noexcept {
      return severity_bits() == static_cast<std::uint32_t>(omni::severity::warning);
    }

    [[nodiscard]] constexpr bool is_error() const noexcept {
      return severity_bits() == static_cast<std::uint32_t>(omni::severity::error);
    }

    [[nodiscard]] constexpr omni::severity severity() const noexcept {
      return static_cast<omni::severity>(severity_bits());
    }

    [[nodiscard]] constexpr omni::facility facility() const noexcept {
      return static_cast<omni::facility>((bits() >> facility_shift) & facility_mask);
    }

    [[nodiscard]] constexpr std::int32_t code() const noexcept {
      return static_cast<std::int32_t>(bits() & code_mask);
    }

    constexpr explicit operator bool() const noexcept {
      return is_success();
    }

    constexpr explicit operator std::int32_t() const noexcept {
      return value;
    }

   private:
    [[nodiscard]] constexpr std::uint32_t bits() const noexcept {
      return static_cast<std::uint32_t>(value);
    }

    [[nodiscard]] constexpr std::uint32_t severity_bits() const noexcept {
      return (bits() >> severity_shift) & severity_mask;
    }

    constexpr static std::uint32_t severity_shift = 30U;
    constexpr static std::uint32_t severity_mask = 0x3U;
    constexpr static std::uint32_t facility_shift = 16U;
    constexpr static std::uint32_t facility_mask = 0x0FFFU;
    constexpr static std::uint32_t code_mask = 0xFFFFU;
  };

  namespace ntstatus {
    [[maybe_unused]] constexpr inline omni::status success{static_cast<std::int32_t>(0x00000000)};
    [[maybe_unused]] constexpr inline omni::status pending{static_cast<std::int32_t>(0x00000103)};
    [[maybe_unused]] constexpr inline omni::status timeout{static_cast<std::int32_t>(0x00000102)};
    [[maybe_unused]] constexpr inline omni::status more_entries{static_cast<std::int32_t>(0x00000105)};
    [[maybe_unused]] constexpr inline omni::status no_more_entries{static_cast<std::int32_t>(0x8000001A)};
    [[maybe_unused]] constexpr inline omni::status no_more_files{static_cast<std::int32_t>(0x80000006)};
    [[maybe_unused]] constexpr inline omni::status buffer_overflow{static_cast<std::int32_t>(0x80000005)};

    [[maybe_unused]] constexpr inline omni::status unsuccessful{static_cast<std::int32_t>(0xC0000001)};
    [[maybe_unused]] constexpr inline omni::status not_implemented{static_cast<std::int32_t>(0xC0000002)};
    [[maybe_unused]] constexpr inline omni::status not_supported{static_cast<std::int32_t>(0xC00000BB)};
    [[maybe_unused]] constexpr inline omni::status invalid_info_class{static_cast<std::int32_t>(0xC0000003)};
    [[maybe_unused]] constexpr inline omni::status info_length_mismatch{static_cast<std::int32_t>(0xC0000004)};
    [[maybe_unused]] constexpr inline omni::status invalid_handle{static_cast<std::int32_t>(0xC0000008)};
    [[maybe_unused]] constexpr inline omni::status invalid_parameter{static_cast<std::int32_t>(0xC000000D)};
    [[maybe_unused]] constexpr inline omni::status invalid_parameter_mix{static_cast<std::int32_t>(0xC0000030)};
    [[maybe_unused]] constexpr inline omni::status invalid_parameter_1{static_cast<std::int32_t>(0xC00000EF)};
    [[maybe_unused]] constexpr inline omni::status invalid_parameter_2{static_cast<std::int32_t>(0xC00000F0)};
    [[maybe_unused]] constexpr inline omni::status invalid_parameter_3{static_cast<std::int32_t>(0xC00000F1)};
    [[maybe_unused]] constexpr inline omni::status invalid_parameter_4{static_cast<std::int32_t>(0xC00000F2)};
    [[maybe_unused]] constexpr inline omni::status invalid_parameter_5{static_cast<std::int32_t>(0xC00000F3)};
    [[maybe_unused]] constexpr inline omni::status invalid_parameter_6{static_cast<std::int32_t>(0xC00000F4)};
    [[maybe_unused]] constexpr inline omni::status invalid_parameter_7{static_cast<std::int32_t>(0xC00000F5)};
    [[maybe_unused]] constexpr inline omni::status invalid_parameter_8{static_cast<std::int32_t>(0xC00000F6)};
    [[maybe_unused]] constexpr inline omni::status invalid_parameter_9{static_cast<std::int32_t>(0xC00000F7)};
    [[maybe_unused]] constexpr inline omni::status invalid_parameter_10{static_cast<std::int32_t>(0xC00000F8)};
    [[maybe_unused]] constexpr inline omni::status invalid_parameter_11{static_cast<std::int32_t>(0xC00000F9)};
    [[maybe_unused]] constexpr inline omni::status invalid_parameter_12{static_cast<std::int32_t>(0xC00000FA)};
    [[maybe_unused]] constexpr inline omni::status access_denied{static_cast<std::int32_t>(0xC0000022)};
    [[maybe_unused]] constexpr inline omni::status object_type_mismatch{static_cast<std::int32_t>(0xC0000024)};
    [[maybe_unused]] constexpr inline omni::status invalid_device_request{static_cast<std::int32_t>(0xC0000010)};
    [[maybe_unused]] constexpr inline omni::status illegal_instruction{static_cast<std::int32_t>(0xC000001D)};
    [[maybe_unused]] constexpr inline omni::status noncontinuable_exception{static_cast<std::int32_t>(0xC0000025)};
    [[maybe_unused]] constexpr inline omni::status invalid_disposition{static_cast<std::int32_t>(0xC0000026)};
    [[maybe_unused]] constexpr inline omni::status access_violation{static_cast<std::int32_t>(0xC0000005)};
    [[maybe_unused]] constexpr inline omni::status in_page_error{static_cast<std::int32_t>(0xC0000006)};
    [[maybe_unused]] constexpr inline omni::status buffer_too_small{static_cast<std::int32_t>(0xC0000023)};

    [[maybe_unused]] constexpr inline omni::status no_memory{static_cast<std::int32_t>(0xC0000017)};
    [[maybe_unused]] constexpr inline omni::status conflicting_addresses{static_cast<std::int32_t>(0xC0000018)};
    [[maybe_unused]] constexpr inline omni::status not_mapped_view{static_cast<std::int32_t>(0xC0000019)};
    [[maybe_unused]] constexpr inline omni::status unable_to_free_vm{static_cast<std::int32_t>(0xC000001A)};
    [[maybe_unused]] constexpr inline omni::status unable_to_delete_section{static_cast<std::int32_t>(0xC000001B)};
    [[maybe_unused]] constexpr inline omni::status invalid_view_size{static_cast<std::int32_t>(0xC000001F)};
    [[maybe_unused]] constexpr inline omni::status invalid_file_for_section{static_cast<std::int32_t>(0xC0000020)};
    [[maybe_unused]] constexpr inline omni::status already_committed{static_cast<std::int32_t>(0xC0000021)};
    [[maybe_unused]] constexpr inline omni::status unable_to_decommit_vm{static_cast<std::int32_t>(0xC000002C)};
    [[maybe_unused]] constexpr inline omni::status not_committed{static_cast<std::int32_t>(0xC000002D)};
    [[maybe_unused]] constexpr inline omni::status invalid_page_protection{static_cast<std::int32_t>(0xC0000045)};
    [[maybe_unused]] constexpr inline omni::status memory_not_allocated{static_cast<std::int32_t>(0xC00000A0)};

    [[maybe_unused]] constexpr inline omni::status no_such_device{static_cast<std::int32_t>(0xC000000E)};
    [[maybe_unused]] constexpr inline omni::status no_such_file{static_cast<std::int32_t>(0xC000000F)};
    [[maybe_unused]] constexpr inline omni::status end_of_file{static_cast<std::int32_t>(0xC0000011)};
    [[maybe_unused]] constexpr inline omni::status wrong_volume{static_cast<std::int32_t>(0xC0000012)};
    [[maybe_unused]] constexpr inline omni::status no_media_in_device{static_cast<std::int32_t>(0xC0000013)};
    [[maybe_unused]] constexpr inline omni::status unrecognized_media{static_cast<std::int32_t>(0xC0000014)};
    [[maybe_unused]] constexpr inline omni::status nonexistent_sector{static_cast<std::int32_t>(0xC0000015)};
    [[maybe_unused]] constexpr inline omni::status object_name_invalid{static_cast<std::int32_t>(0xC0000033)};
    [[maybe_unused]] constexpr inline omni::status object_name_not_found{static_cast<std::int32_t>(0xC0000034)};
    [[maybe_unused]] constexpr inline omni::status object_name_collision{static_cast<std::int32_t>(0xC0000035)};
    [[maybe_unused]] constexpr inline omni::status object_path_invalid{static_cast<std::int32_t>(0xC0000039)};
    [[maybe_unused]] constexpr inline omni::status object_path_not_found{static_cast<std::int32_t>(0xC000003A)};
    [[maybe_unused]] constexpr inline omni::status object_path_syntax_bad{static_cast<std::int32_t>(0xC000003B)};
    [[maybe_unused]] constexpr inline omni::status sharing_violation{static_cast<std::int32_t>(0xC0000043)};
    [[maybe_unused]] constexpr inline omni::status delete_pending{static_cast<std::int32_t>(0xC0000056)};
    [[maybe_unused]] constexpr inline omni::status file_is_a_directory{static_cast<std::int32_t>(0xC00000BA)};
    [[maybe_unused]] constexpr inline omni::status file_renamed{static_cast<std::int32_t>(0xC00000D5)};
    [[maybe_unused]] constexpr inline omni::status disk_full{static_cast<std::int32_t>(0xC000007F)};
    [[maybe_unused]] constexpr inline omni::status crc_error{static_cast<std::int32_t>(0xC000003F)};
    [[maybe_unused]] constexpr inline omni::status media_write_protected{static_cast<std::int32_t>(0xC00000A2)};

    [[maybe_unused]] constexpr inline omni::status procedure_not_found{static_cast<std::int32_t>(0xC000007A)};
    [[maybe_unused]] constexpr inline omni::status invalid_image_format{static_cast<std::int32_t>(0xC000007B)};
    [[maybe_unused]] constexpr inline omni::status dll_not_found{static_cast<std::int32_t>(0xC0000135)};
    [[maybe_unused]] constexpr inline omni::status ordinal_not_found{static_cast<std::int32_t>(0xC0000138)};
    [[maybe_unused]] constexpr inline omni::status entrypoint_not_found{static_cast<std::int32_t>(0xC0000139)};
    [[maybe_unused]] constexpr inline omni::status image_not_at_base{static_cast<std::int32_t>(0x40000003)};
    [[maybe_unused]] constexpr inline omni::status object_name_exists{static_cast<std::int32_t>(0x40000000)};

    [[maybe_unused]] constexpr inline omni::status thread_is_terminating{static_cast<std::int32_t>(0xC000004B)};
    [[maybe_unused]] constexpr inline omni::status suspend_count_exceeded{static_cast<std::int32_t>(0xC000004A)};
    [[maybe_unused]] constexpr inline omni::status process_not_in_job{static_cast<std::int32_t>(0x00000123)};
    [[maybe_unused]] constexpr inline omni::status process_in_job{static_cast<std::int32_t>(0x00000124)};

    [[maybe_unused]] constexpr inline omni::status invalid_owner{static_cast<std::int32_t>(0xC000005A)};
    [[maybe_unused]] constexpr inline omni::status invalid_primary_group{static_cast<std::int32_t>(0xC000005B)};
    [[maybe_unused]] constexpr inline omni::status no_impersonation_token{static_cast<std::int32_t>(0xC000005C)};
    [[maybe_unused]] constexpr inline omni::status cant_disable_mandatory{static_cast<std::int32_t>(0xC000005D)};
    [[maybe_unused]] constexpr inline omni::status no_logon_servers{static_cast<std::int32_t>(0xC000005E)};
    [[maybe_unused]] constexpr inline omni::status no_such_logon_session{static_cast<std::int32_t>(0xC000005F)};
    [[maybe_unused]] constexpr inline omni::status no_such_privilege{static_cast<std::int32_t>(0xC0000060)};
    [[maybe_unused]] constexpr inline omni::status privilege_not_held{static_cast<std::int32_t>(0xC0000061)};
    [[maybe_unused]] constexpr inline omni::status invalid_account_name{static_cast<std::int32_t>(0xC0000062)};
    [[maybe_unused]] constexpr inline omni::status user_exists{static_cast<std::int32_t>(0xC0000063)};
    [[maybe_unused]] constexpr inline omni::status no_such_user{static_cast<std::int32_t>(0xC0000064)};
    [[maybe_unused]] constexpr inline omni::status group_exists{static_cast<std::int32_t>(0xC0000065)};
    [[maybe_unused]] constexpr inline omni::status no_such_group{static_cast<std::int32_t>(0xC0000066)};
    [[maybe_unused]] constexpr inline omni::status member_in_group{static_cast<std::int32_t>(0xC0000067)};
    [[maybe_unused]] constexpr inline omni::status member_not_in_group{static_cast<std::int32_t>(0xC0000068)};
    [[maybe_unused]] constexpr inline omni::status wrong_password{static_cast<std::int32_t>(0xC000006A)};
    [[maybe_unused]] constexpr inline omni::status logon_failure{static_cast<std::int32_t>(0xC000006D)};
    [[maybe_unused]] constexpr inline omni::status account_disabled{static_cast<std::int32_t>(0xC0000072)};
    [[maybe_unused]] constexpr inline omni::status not_all_assigned{static_cast<std::int32_t>(0x00000106)};
    [[maybe_unused]] constexpr inline omni::status some_not_mapped{static_cast<std::int32_t>(0x00000107)};

    [[maybe_unused]] constexpr inline omni::status port_connection_refused{static_cast<std::int32_t>(0xC0000041)};
    [[maybe_unused]] constexpr inline omni::status port_disconnected{static_cast<std::int32_t>(0xC0000037)};
    [[maybe_unused]] constexpr inline omni::status invalid_port_handle{static_cast<std::int32_t>(0xC0000042)};
    [[maybe_unused]] constexpr inline omni::status invalid_port_attributes{static_cast<std::int32_t>(0xC000002E)};
    [[maybe_unused]] constexpr inline omni::status port_message_too_long{static_cast<std::int32_t>(0xC000002F)};
    [[maybe_unused]] constexpr inline omni::status pipe_disconnected{static_cast<std::int32_t>(0xC00000B0)};
    [[maybe_unused]] constexpr inline omni::status io_timeout{static_cast<std::int32_t>(0xC00000B5)};
    [[maybe_unused]] constexpr inline omni::status already_disconnected{static_cast<std::int32_t>(0x80000025)};

    [[maybe_unused]] constexpr inline omni::status notify_cleanup{static_cast<std::int32_t>(0x0000010B)};
    [[maybe_unused]] constexpr inline omni::status notify_enum_dir{static_cast<std::int32_t>(0x0000010C)};
  } // namespace ntstatus

} // namespace omni

template <>
struct std::formatter<omni::status> : std::formatter<std::uint32_t> {
  auto format(const omni::status& status, std::format_context& ctx) const {
    return std::formatter<std::uint32_t>::format(static_cast<std::uint32_t>(status.value), ctx);
  }
};
