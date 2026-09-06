#pragma once

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <iterator>
#include <memory>
#include <ranges>
#include <string_view>
#include <system_error>
#include <utility>

#include "omni/allocator.hpp"
#include "omni/handle.hpp"
#include "omni/win/system_process_information.hpp"

namespace omni {

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
      process_access access = process_access::query_limited_information) const noexcept;

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
      // TODO: Implement this. Let's set max NtQuerySystemInformation
      // attempts to ~8 at most

      allocator_type allocator;

      return std::unexpected(std::make_error_code(std::errc::not_supported));
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
        allocator_type allocator;
        allocator.deallocate(p, 0);
      }
    };
    using buffer = std::unique_ptr<std::byte, virtual_free>;

    // TODO: Required by ::snapshot()
    explicit processes(buffer storage) noexcept;

    buffer storage_;
  };

  static_assert(std::ranges::forward_range<processes>);

} // namespace omni
