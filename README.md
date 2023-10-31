# shadow syscalls [![](https://img.shields.io/badge/version-1.0.1-green.svg)]()

Easy to use syscall wrapper based on MASM. Each call is hashed using intrins and is not reverse-engineer friendly.
Second repository branch - **shellcode** realization without **MASM**

Target platform (as of today) - MSVC, x64 Release & Debug

## Example of simple call
 
```cpp
int main(void)
{
    shadowsyscall(NTSTATUS, NtTerminateProcess).invoke((HANDLE)0xDEADC0DE, -1);

    return EXIT_SUCCESS;
}
```

## Detailed example

```cpp
int main(void)
{
    auto instance = shadowsyscall(NTSTATUS, NtTerminateProcess);

    // cache index before executing syscall, unnecessarily
    instance.cache_index();

    // get NtTerminateProcess syscall index
    instance.syscall_index();

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
![image](https://github.com/annihilatorq/shadow_syscall/assets/143023834/41db77b2-7fdb-4e5f-a0a1-d266504da9e5)

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

## IDA Pro Pseudocode Output
`#define SHADOWSYSCALL_DISABLE_EXCEPTIONS`
```c
v2 = a2;
  v38 = a2;
  *a2 = -804903540;
  v3 = 0;
  a2[1] = 0;
  v4 = (void **)sub_140001540(&v41);
  v5 = v4;
  v6 = *v4;
  v7 = (_QWORD *)*((_QWORD *)*v4 + 1);
  v8 = *v4;
  v9 = *((_BYTE *)v7 + 25);
  if ( !v9 )
  {
    v10 = (_QWORD *)*((_QWORD *)*v4 + 1);
    do
    {
      if ( *((_DWORD *)v10 + 7) >= 0xD006258C )
      {
        v8 = v10;
        v10 = (_QWORD *)*v10;
      }
      else
      {
        v10 = (_QWORD *)v10[2];
      }
    }
    while ( !*((_BYTE *)v10 + 25) );
  }
  if ( v8[25] || *((_DWORD *)v8 + 7) > 0xD006258C )
    v8 = v6;
  if ( !v9 )
  {
    do
    {
      sub_1400017B0(v5, v5, v7[2]);
      v11 = v7;
      v7 = (_QWORD *)*v7;
      j_j_free(v11);
    }
    while ( !*((_BYTE *)v7 + 25) );
  }
  j_j_free(*v5);
  if ( v8 != v6 )
  {
    v12 = Block;
    v13 = (_QWORD *)*((_QWORD *)Block + 1);
    while ( !*((_BYTE *)v13 + 25) )
    {
      if ( *((_DWORD *)v13 + 7) >= *v2 )
      {
        v12 = v13;
        v13 = (_QWORD *)*v13;
      }
      else
      {
        v13 = (_QWORD *)v13[2];
      }
    }
    if ( !*((_BYTE *)v12 + 25) && *v2 >= v12[7] )
    {
      v2[1] = v12[8];
      return v2;
    }
    std::_Xout_of_range("invalid map<K, T> key");
  }
  v14 = *v2;
  v39 = &NtCurrentPeb()->Ldr->Reserved2[1];
  v15 = (PVOID *)*v39;
  if ( *v39 != v39 )
  {
    v40 = 1209689126;
    v16 = v39;
    do
    {
      if ( v15[12] )
      {
        v17 = (int *)v15[6];
        if ( *(_WORD *)v17 == 23117 )
        {
          v18 = v17[15];
          if ( *(_WORD *)((char *)v17 + v18 + 24) != 523 || *(int *)((char *)v17 + v18 + 140) )
          {
            v19 = *(unsigned int *)((char *)v17 + v18 + 136);
            v20 = (__int64)v17 + *(unsigned int *)((char *)v17 + v19 + 32);
            v21 = (__int64)v17 + *(unsigned int *)((char *)v17 + v19 + 28);
            v41 = (__int64)v17 + *(unsigned int *)((char *)v17 + v19 + 36);
            v22 = 0i64;
            v23 = *(unsigned int *)((char *)v17 + v19 + 24);
            if ( *(int *)((char *)v17 + v19 + 24) )
            {
              while ( 1 )
              {
                v24 = (__int64)v17 + *(unsigned int *)(v20 + 4 * v22);
                v25 = -2095942872;
                v26 = 0i64;
                do
                  ++v26;
                while ( *(_BYTE *)(v26 + v24) );
                v27 = 0i64;
                if ( v26 )
                {
                  do
                  {
                    v28 = *(char *)(v27 + v24);
                    if ( v25 == v28 )
                    {
                      v29 = 0;
                    }
                    else
                    {
                      v30 = (__m128)_mm_cvtsi32_si128(v28);
                      v31 = (__m128)_mm_cvtsi32_si128(v25);
                      v29 = _mm_cvtsi128_si32((__m128i)_mm_or_ps(
                                                         _mm_andnot_ps(v31, v30),
                                                         _mm_and_ps(_mm_andnot_ps(v30, (__m128)xmmword_140003370), v31)));
                    }
                    v32 = v27;
                    if ( !v27 )
                      v32 = v40;
                    if ( v32 == 268338 )
                    {
                      v33 = 0;
                    }
                    else
                    {
                      v34 = (__m128)_mm_cvtsi32_si128(v32);
                      v35 = (__m128)_mm_cvtsi32_si128(0x41832u);
                      v33 = _mm_cvtsi128_si32((__m128i)_mm_or_ps(
                                                         _mm_andnot_ps(v35, v34),
                                                         _mm_and_ps(_mm_andnot_ps(v34, (__m128)xmmword_140003370), v35)));
                    }
                    v25 = v28
                        + _mm_cvtsi128_si32(_mm_shuffle_epi32(_mm_cvtsi32_si128(v29 + v28 * (v27++ + 1209689126)), 0))
                        * v33;
                  }
                  while ( v27 < v26 );
                  v17 = (int *)v15[6];
                }
                if ( v14 == v25 )
                  break;
                if ( ++v22 >= v23 )
                  goto LABEL_46;
              }
              v36 = (__int64)v17 + *(unsigned int *)(v21 + 4i64 * *(unsigned __int16 *)(v41 + 2 * v22));
              if ( v36 )
                goto LABEL_50;
            }
LABEL_46:
            v16 = v39;
          }
        }
      }
      v15 = (PVOID *)*v15;
    }
    while ( v15 != v16 );
    v2 = v38;
  }
  v36 = v41;
  if ( v41 )
  {
LABEL_50:
    v3 = *(_DWORD *)(v36 + 4);
    v2 = v38;
  }
  v2[1] = v3;
  v38 = (unsigned int *)__PAIR64__(v3, v14);
  sub_140001620(v36, v42, &v38);
  return v2;
```

## Thanks to
invers1on :heart:, metafaze :heart:
