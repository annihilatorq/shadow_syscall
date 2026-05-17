#pragma once

#include <array>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <type_traits>
#include <utility>

#include "omni/allocator.hpp"

namespace omni::detail {

  template <std::uint32_t Size>
  class shellcode {
   public:
    using storage_type = std::array<std::uint8_t, Size>;

    explicit shellcode(storage_type shellcode) noexcept: shellcode_(shellcode) {}

    shellcode(const shellcode&) = delete;
    shellcode(shellcode&& other) noexcept
      : memory_(std::exchange(other.memory_, nullptr)), allocator_(other.allocator_), shellcode_(std::move(other.shellcode_)) {}
    shellcode& operator=(const shellcode&) = delete;
    shellcode& operator=(shellcode&& other) noexcept {
      if (this == std::addressof(other)) {
        return *this;
      }

      reset();
      allocator_ = other.allocator_;
      shellcode_ = std::move(other.shellcode_);
      memory_ = std::exchange(other.memory_, nullptr);
      return *this;
    }

    ~shellcode() noexcept {
      reset();
    }

    void setup() {
      reset();
      memory_ = allocator_.allocate(Size);
      std::memcpy(memory_, shellcode_.data(), Size);
    }

    template <std::integral T = std::uint8_t>
    [[nodiscard]] T read(std::size_t index) const noexcept {
      return shellcode_[index];
    }

    template <std::integral T>
    void write(std::size_t index, T value) noexcept {
      *reinterpret_cast<T*>(&shellcode_[index]) = value;
    }

    template <typename T, typename... Args>
      requires(std::is_default_constructible_v<T>)
    [[nodiscard]] T execute(Args&&... args) const noexcept {
      if (!memory_) {
        return T{};
      }
      return reinterpret_cast<T(__stdcall*)(Args...)>(memory_)(args...);
    }

    template <typename T = void, typename... Args>
      requires(std::is_void_v<T>)
    [[nodiscard]] T execute(Args&&... args) const noexcept {
      if (!memory_) {
        return;
      }
      reinterpret_cast<void(__stdcall*)(Args...)>(memory_)(args...);
    }

    template <typename T = void, typename PointerT = std::add_pointer_t<T>>
    [[nodiscard]] PointerT ptr() const noexcept {
      return static_cast<PointerT>(memory_);
    }

   private:
    void reset() noexcept {
      if (memory_ == nullptr) {
        return;
      }

      allocator_.deallocate(memory_, Size);
      memory_ = nullptr;
    }

    std::uint8_t* memory_{nullptr};
    rwx_allocator<std::uint8_t> allocator_;
    std::array<std::uint8_t, Size> shellcode_{};
  };

} // namespace omni::detail
