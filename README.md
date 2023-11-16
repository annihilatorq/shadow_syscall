# shadow syscalls [![](https://img.shields.io/badge/version-1.0.1-green.svg)]()

Easy to use syscall wrapper based on shellcode. Each call is hashed using intrins and is not reverse-engineer friendly.

Target platform (as of today) - MSVC (no others have been tested), x64 Release & Debug, CPP 17 - 23

## Simple example

```cpp
int main(void)
{
    shadowsyscall(NTSTATUS, NtTerminateProcess).invoke((HANDLE)0xDEADC0DE, -1);

    return EXIT_SUCCESS;
}
```

Shellcode uses VirtualAlloc and VirtualFree function wrappers from *kernelbase.dll*, memory allocation itself is based on ```NtAllocateVirtualMemory | NtFreeVirtualMemory```, which are executed in runtime by addresses of these routines.

https://github.com/annihilatorq/shadow_syscall/blob/e0c736bf4a5de217ae0f0a6b4b11f5886e667771/include/shadow%20syscall%20shellcode.hpp#L500-L507

## Detailed example

```cpp
int main(void)
{
    auto instance = shadowsyscall(NTSTATUS, NtTerminateProcess);

    // insert index into the cache before executing syscall, unnecessarily
    instance.insert_index();

    // get NtTerminateProcess syscall index
    uint32_t index = instance.syscall_index();

    // execute NtTerminateProcess syscall
    NTSTATUS status = instance.invoke((HANDLE)0xDEADC0DE, -1);

    std::cout << "syscall status: " << "0x" << std::hex << status << std::endl;

    return EXIT_SUCCESS;
}
```

## 🚀 Features

- Caching each call.
- Ability to disable exceptions within the code.
- Doesn't leave any strings in executable memory.
- Compile-time hashing export.
- Runtime hash based on intrins.
- Doesn't leave any imports in the executable.
- Ability to switch between SSE and AVX intrins.

## 📜 What's a syscall?
![syscall_architecture](https://github.com/annihilatorq/shadow_syscall/assets/143023834/63f46089-a590-4c6b-aa60-447b536ece34)

## ⏲️ Benchmarks - call caching
Each test calculates the average of 100 syscalls to the same nt-api.
syscall used: **NtReadVirtualMemory**

Benchmark time is measured in `microseconds`
```
Map-cached calls, the result: 0.72ms  -  1.12ms per call.  70.2ms per hundred calls.

Non-cached calls, the result: 38.54ms - 52.61ms per call.  3854ms per hundred calls.
```

The difference between call caching and regular call is obvious, the whole point is that when caching calls - the syscall index is stored in the `std::map` container, then the first thing is to check the presence of the index by the necessary hash when calling the syscall.

If the corresponding syscall index is found by hash in `std::map`, then rolling up the list of modules and their exports through PEB is not required, thus we eliminate several cycles before making the call itself. This is how we achieve such performance.

## 📄 Documentation

- `shadowsyscall_hashct(str)              -> compile-time hash`
- `shadowsyscall_hashrt(str)              -> runtime hash`
- `shadowsyscall(type, export_name)       -> class wrapper allows you to call some methods, also includes .invoke() method`
- `shadowsyscall_(type, export_name, ...) -> syscall executor`

## 🛠️ Configuration

| `#define`                                 | EFFECT                                                                                  |
| ----------------------------------------- | --------------------------------------------------------------------------------------- |
| `SHADOWSYSCALL_NO_FORCEINLINE`            | disables force inlining                                                                 |
| `SHADOWSYSCALL_DISABLE_EXCEPTIONS`        | disables all exceptions and returns 0 if the function fails.                            |
| `SHADOWSYSCALL_DISABLE_INTRIN_HASH`       | disables runtime intrin-based hashing, and leaves normal arithmetic operations in place |
| `SHADOWSYSCALL_NO_CACHING`                | completely disables caching of all syscalls.                                            |
| `SHADOWSYSCALL_USE_AVX_INTRINS`           | use only AVX in the hashing algorithm instead of SSE intrins                         |

## Thanks to
invers1on :heart:
