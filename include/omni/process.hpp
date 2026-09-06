#pragma once

#include <algorithm>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <iterator>
#include <limits>
#include <memory>
#include <new>
#include <ranges>
#include <string_view>
#include <system_error>
#include <utility>

#include "omni/allocator.hpp"
#include "omni/handle.hpp"
#include "omni/lazy_import.hpp"
#include "omni/syscall.hpp"
#include "omni/win/system_process_information.hpp"

namespace omni {

  namespace detail {

    struct process_client_id {
      void* unique_process;
      void* unique_thread;
    };

    struct process_object_attributes {
      std::uint32_t length;
      void* root_directory;
      void* object_name;
      std::uint32_t attributes;
      void* security_descriptor;
      void* security_quality_of_service;
    };

    static_assert(sizeof(process_client_id) == sizeof(void*) * 2);
    static_assert(sizeof(process_object_attributes) == (sizeof(void*) == 8 ? 0x30 : 0x18));

#ifdef OMNI_ARCH_X86
    using query_system_information_fn = omni::status(__stdcall*)(std::uint32_t, void*, std::uint32_t, std::uint32_t*);
    using open_process_fn = omni::status(__stdcall*)(void**, std::uint32_t, process_object_attributes*, process_client_id*);
#else
    using query_system_information_fn = omni::status (*)(std::uint32_t, void*, std::uint32_t, std::uint32_t*);
    using open_process_fn = omni::status (*)(void**, std::uint32_t, process_object_attributes*, process_client_id*);
#endif

#ifdef OMNI_ARCH_X64
#  ifdef OMNI_HAS_INLINE_SYSCALL
    using process_syscaller = omni::inline_syscaller<omni::status>;
#  else
    using process_syscaller = omni::syscaller<omni::status>;
#  endif
    using process_query_caller = process_syscaller;
    using process_open_caller = process_syscaller;
#else
    using process_query_caller = omni::lazy_importer<query_system_information_fn>;
    using process_open_caller = omni::lazy_importer<open_process_fn>;
#endif

    [[nodiscard]] inline bool process_query_needs_resize(omni::status status) noexcept {
      return status == omni::ntstatus::info_length_mismatch || status == omni::ntstatus::buffer_too_small;
    }

    [[nodiscard]] inline std::error_code process_status_error(omni::status status) noexcept {
      return omni::make_error_code(status);
    }

  } // namespace detail

  enum class process_access : std::uint32_t {
    query_limited_information = 0x1000,
  };

  [[nodiscard]] constexpr process_access operator|(process_access lhs, process_access rhs) noexcept {
    return static_cast<process_access>(std::to_underlying(lhs) | std::to_underlying(rhs));
  }

  [[nodiscard]] constexpr process_access operator&(process_access lhs, process_access rhs) noexcept {
    return static_cast<process_access>(std::to_underlying(lhs) & std::to_underlying(rhs));
  }

  constexpr process_access& operator|=(process_access& lhs, process_access rhs) noexcept {
    return lhs = lhs | rhs;
  }

  class process {
   public:
    [[nodiscard]] std::expected<omni::unique_handle, std::error_code> open_handle(
      process_access access = process_access::query_limited_information) const noexcept {
#ifdef OMNI_HAS_EXCEPTIONS
      try {
#endif
        detail::process_client_id client_id{
          .unique_process = reinterpret_cast<void*>(static_cast<std::uintptr_t>(id())),
          .unique_thread = nullptr,
        };
        detail::process_object_attributes object_attributes{
          .length = sizeof(detail::process_object_attributes),
          .root_directory = nullptr,
          .object_name = nullptr,
          .attributes = 0,
          .security_descriptor = nullptr,
          .security_quality_of_service = nullptr,
        };
        native_handle handle{};

        detail::process_open_caller open_process{"NtOpenProcess"};
        auto result = open_process.try_invoke(&handle, std::to_underlying(access), &object_attributes, &client_id);
        if (!result) {
          return std::unexpected(result.error());
        }
        if (!result->is_success()) {
          return std::unexpected(detail::process_status_error(*result));
        }

        return omni::unique_handle{handle};
#ifdef OMNI_HAS_EXCEPTIONS
      } catch (const std::bad_alloc&) {
        return std::unexpected(omni::make_error_code(omni::ntstatus::no_memory));
      } catch (...) {
        return std::unexpected(omni::make_error_code(omni::ntstatus::unsuccessful));
      }
#endif
    }

    [[nodiscard]] std::uint32_t id() const noexcept {
      return static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(info_->unique_process_id));
    }

    [[nodiscard]] std::uint32_t parent_id() const noexcept {
      return static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(info_->inherited_from_unique_process_id));
    }

    [[nodiscard]] std::uint32_t session_id() const noexcept {
      return info_->session_id;
    }

    [[nodiscard]] std::uint32_t thread_count() const noexcept {
      return info_->number_of_threads;
    }

    [[nodiscard]] std::wstring_view name() const noexcept {
      return info_->image_name.view();
    }

    [[nodiscard]] const win::system_process_information& info() const noexcept {
      return *info_;
    }

   private:
    friend class processes;
    explicit process(const win::system_process_information* info) noexcept: info_(info) {
      assert(info_ != nullptr);
    }

    const win::system_process_information* info_;
  };

  class processes {
   public:
    using allocator_type = omni::nt_allocator<std::byte, mem::commit_reserve, mem::page::read_write>;

    class iterator {
     public:
      using value_type = process;
      using difference_type = std::ptrdiff_t;
      using iterator_concept = std::forward_iterator_tag;

      iterator() noexcept = default;

      [[nodiscard]] process operator*() const noexcept {
        return process{current_};
      }

      iterator& operator++() noexcept {
        const std::uint32_t offset = current_->next_entry_offset;
        if (offset == 0) {
          current_ = nullptr;
        } else {
          const auto* next_location = reinterpret_cast<const std::byte*>(current_) + offset;
          current_ = reinterpret_cast<const win::system_process_information*>(next_location);
        }
        return *this;
      }

      iterator operator++(int) noexcept {
        const iterator previous = *this;
        ++*this;
        return previous;
      }

      [[nodiscard]] friend bool operator==(const iterator&, const iterator&) noexcept = default;

     private:
      friend class processes;
      explicit iterator(const win::system_process_information* current) noexcept: current_{current} {}

      const win::system_process_information* current_{nullptr};
    };

    static_assert(std::forward_iterator<processes::iterator>);

    [[nodiscard]] static std::expected<processes, std::error_code> snapshot() noexcept {
#ifdef OMNI_HAS_EXCEPTIONS
      try {
#endif
        allocator_type allocator;
        detail::process_query_caller query_system_information{"NtQuerySystemInformation"};

        constexpr std::size_t max_attempts = 8;
        constexpr std::uint32_t default_buffer_size = 64U * 1024U;
        std::uint32_t return_length{};
        auto sizing_result = query_system_information.try_invoke(5U, nullptr, 0U, &return_length);
        if (!sizing_result) {
          return std::unexpected(sizing_result.error());
        }
        if (!sizing_result->is_success() && !detail::process_query_needs_resize(*sizing_result)) {
          return std::unexpected(detail::process_status_error(*sizing_result));
        }

        std::uint32_t buffer_size = return_length == 0U ? default_buffer_size : return_length;
        buffer storage;

        for (std::size_t attempt = 1; attempt < max_attempts; ++attempt) {
          storage.reset(allocator.allocate(buffer_size));
          return_length = 0U;
          auto result = query_system_information.try_invoke(5U, storage.get(), buffer_size, &return_length);
          if (!result) {
            return std::unexpected(result.error());
          }
          if (result->is_success()) {
            return processes{std::move(storage)};
          }
          if (!detail::process_query_needs_resize(*result)) {
            return std::unexpected(detail::process_status_error(*result));
          }

          storage.reset();
          if (buffer_size > (std::numeric_limits<std::uint32_t>::max)() / 2U) {
            return std::unexpected(detail::process_status_error(omni::ntstatus::buffer_too_small));
          }
          buffer_size = (std::max)(return_length, buffer_size * 2U);
        }

        return std::unexpected(detail::process_status_error(omni::ntstatus::info_length_mismatch));
#ifdef OMNI_HAS_EXCEPTIONS
      } catch (const std::bad_alloc&) {
        return std::unexpected(omni::make_error_code(omni::ntstatus::no_memory));
      } catch (...) {
        return std::unexpected(omni::make_error_code(omni::ntstatus::unsuccessful));
      }
#endif
    }

    processes(processes&&) noexcept = default;
    processes& operator=(processes&&) noexcept = default;
    processes(const processes&) = delete;
    processes& operator=(const processes&) = delete;
    ~processes() = default;

    [[nodiscard]] iterator begin() const noexcept {
      if (!storage_) {
        return end();
      }

      // TODO: Check if C++23 std::start_lifetime_as is available for all
      // stdlibs that omni currently supports
      return iterator{reinterpret_cast<const win::system_process_information*>(storage_.get())};
    }

    [[nodiscard]] iterator end() const noexcept {
      return iterator{nullptr};
    }

   private:
    struct virtual_free {
      void operator()(std::byte* p) const noexcept {
        if (p == nullptr) {
          return;
        }
        allocator_type allocator;
        allocator.deallocate(p, 0);
      }
    };
    using buffer = std::unique_ptr<std::byte, virtual_free>;

    explicit processes(buffer storage) noexcept: storage_(std::move(storage)) {}

    buffer storage_;
  };

  static_assert(std::ranges::forward_range<processes>);

} // namespace omni
