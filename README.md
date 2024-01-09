# shadow syscalls

Easy to use syscall wrapper based on shellcode. Each call is hashed using intrins and is not reverse-engineer friendly.

Target platform (as of today) - MSVC (no others have been tested), x64 Release & Debug, CPP 14 - 23

### Quick example
```cpp
shadowsyscall(NTSTATUS, NtTerminateProcess).call((HANDLE)0xDEADC0DE, -1);
```

Shellcode uses VirtualAlloc and VirtualFree function wrappers from *kernelbase.dll*, memory allocation itself is based on ```NtAllocateVirtualMemory | NtFreeVirtualMemory```, which are executed in runtime by addresses of these routines.

https://github.com/annihilatorq/shadow_syscall/blob/61e2787cb352b9cab3bc4ce211803c2374a6bd86/include/shadow%20syscall%20shellcode.hpp#L587-L601

## Detailed example

```cpp
int main(void)
{
    NTSTATUS result = 0;

    // Execute "NtTerminateProcess" syscall
    shadowsyscall(NTSTATUS, NtTerminateProcess).call((HANDLE)0xDEADC0DE, -1);

    // NtTerminateProcess cached call
    for (int i = 0; i < 5; ++i)
        result = shadowsyscall(NTSTATUS, NtTerminateProcess).cached_call((HANDLE)0xDEADC0DE, -1);

    // Check for return value
    std::cout << "Last NtTerminateProcess return value: 0x" << std::hex << result << '\n';

    // As expected, console output is - 0xc0000008, which refers to STATUS_INVALID_HANDLE
    // More about NTSTATUS error handling below:
    // https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55

    return EXIT_SUCCESS;
}
```

## 🚀 Features

- Caching each call.
- Ability to disable exceptions within the code.
- Doesn't leave any strings in executable memory.
- Compile-time hashing export.
- Hash seed is pseudo-randomized, based on compilation time.
- Runtime hash based on intrins.
- Doesn't leave any imports in the executable.
- Ability to switch between SSE and AVX intrins.
- Header includes only ```<intrin.h>``` so that the compilation time is minimized.

## 📜 What's a syscall?
![syscall_architecture](https://github.com/annihilatorq/shadow_syscall/assets/143023834/63f46089-a590-4c6b-aa60-447b536ece34)

## 📄 Documentation

- `SHADOWSYSCALL_COMPILETIME_HASH(str)    -> compile-time hash`
- `SHADOWSYSCALL_RUNTIME_HASH(str)        -> runtime hash`
- `shadowsyscall(type, syscall_name)      -> class wrapper allows you to call some methods, also includes .call() and .cached_call() method`

## 🛠️ Configuration

| `#define`                                 | EFFECT                                                                                  |
| ----------------------------------------- | --------------------------------------------------------------------------------------- |
| `SHADOWSYSCALL_NO_FORCEINLINE`            | disables force inlining                                                                 |
| `SHADOWSYSCALL_DISABLE_EXCEPTIONS`        | disables all exceptions and returns 0 if the function fails.                            |
| `SHADOWSYSCALL_DISABLE_INTRIN_HASH`       | disables runtime intrin-based hashing, and leaves normal arithmetic operations in place |
| `SHADOWSYSCALL_NO_CACHING`                | completely disables caching of all syscalls.                                            |
| `SHADOWSYSCALL_USE_AVX_INTRINS`           | use only AVX in the hashing algorithm instead of SSE intrins                            |
| `SHADOWSYSCALL_CASE_INSENSITIVE`          | disables case sensitivity in the hashing algorithm                                      |

## Thanks to
invers1on :heart:
