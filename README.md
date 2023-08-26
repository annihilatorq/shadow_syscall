# shadow syscalls [![](https://img.shields.io/badge/version-1.0.0-green.svg)]()

Easy to use syscall wrapper based on MASM. Each call is hashed using intrins and is not reverse-engineer friendly.

## Example of simple call

```cpp
//                              typename, Nt/Zw export, args:  HANDLE   , ExitCode
NTSTATUS status = shadowsyscall(NTSTATUS, NtTerminateProcess, (HANDLE)-1, 0);
```

## Features

- Caching each call.
- Ability to disable exceptions within the code.
- Doesn't leave any strings in executable memory.
- Compile-time hashing export.
- Runtime hash based on intrins.
- Doesn't leave any imports in the executable.
- Randomized hash seed based on compilation time.

## Documentation

- `hash_ct_shadowsyscall(str)            -> compile-time hash`
- `hash_rt_shadowsyscall(str)            -> runtime hash`
- `shadowsyscall(type, export_name, ...) -> syscall function`

## Configuration

| `#define`                                 | EFFECT                                                                                  |
| ----------------------------------------- | --------------------------------------------------------------------------------------- |
| `SHADOWSYSCALL_NO_FORCEINLINE`            | disables force inlining                                                                 |
| `SHADOWSYSCALL_DISABLE_EXCEPTIONS`        | disables all exceptions and returns 0 if the function fails.                            |
| `SHADOWSYSCALL_DISABLE_INTRIN_HASH`       | disables runtime intrin-based hashing, and leaves normal arithmetic operations in place |
| `SHADOWSYSCALL_NO_CACHING`                | completely disables caching of all syscalls.                                            |

## IDA Pro Pseudocode Output
`#define SHADOWSYSCALL_DISABLE_EXCEPTIONS`
```c
v1 = (_DWORD *)(*(_QWORD *)NtCurrentTeb()->ThreadLocalStoragePointer + 4i64);
  v30 = v1;
  if ( dword_14000568C > *v1 )
  {
    Init_thread_header(&dword_14000568C);
    if ( dword_14000568C == -1 )
    {
      qword_140005698 = 959029059i64;
      if ( dword_140005684 > *v1 )
      {
        Init_thread_header(&dword_140005684);
        if ( dword_140005684 == -1 )
        {
          v3 = qword_140005698;
          LODWORD(v27) = qword_140005698;
          v28 = &NtCurrentPeb()->Ldr->Reserved2[1];
          v4 = (PVOID *)*v28;
          v5 = v28;
          if ( *v28 != v28 )
          {
            v2 = 523i64;
            do
            {
              if ( v4[12] )
              {
                v6 = (int *)v4[6];
                if ( *(_WORD *)v6 == 23117 )
                {
                  v7 = v6[15];
                  if ( *(_WORD *)((char *)v6 + v7 + 24) != 523 || *(int *)((char *)v6 + v7 + 140) )
                  {
                    v8 = *(unsigned int *)((char *)v6 + v7 + 136);
                    v9 = (__int64)v6 + *(unsigned int *)((char *)v6 + v8 + 32);
                    v10 = (__int64)v6 + *(unsigned int *)((char *)v6 + v8 + 28);
                    v29 = (__int64)v6 + *(unsigned int *)((char *)v6 + v8 + 36);
                    v11 = 0i64;
                    v12 = *(unsigned int *)((char *)v6 + v8 + 24);
                    if ( *(int *)((char *)v6 + v8 + 24) )
                    {
                      while ( 1 )
                      {
                        v13 = (__int64)v6 + *(unsigned int *)(v9 + 4 * v11);
                        v14 = -2095942872;
                        v5 = 0i64;
                        do
                          v5 = (PVOID *)((char *)v5 + 1);
                        while ( *((_BYTE *)v5 + v13) );
                        v15 = 0i64;
                        if ( v5 )
                        {
                          do
                          {
                            v2 = (unsigned int)*(char *)(v15 + v13);
                            if ( v14 == (_DWORD)v2 )
                            {
                              v16 = 0;
                            }
                            else
                            {
                              v17 = _mm_cvtsi32_si128(v2);
                              v18 = _mm_cvtsi32_si128(v14);
                              v16 = _mm_cvtsi128_si32(
                                      _mm_or_si128(
                                        _mm_andnot_si128(v18, v17),
                                        _mm_and_si128(v18, _mm_andnot_si128(v17, (__m128i)xmmword_1400033F0))));
                            }
                            v19 = v15;
                            if ( !v15 )
                              v19 = 321;
                            if ( v19 == 268338 )
                            {
                              v20 = 0;
                            }
                            else
                            {
                              v21 = _mm_cvtsi32_si128(v19);
                              v22 = _mm_cvtsi32_si128(0x41832u);
                              v20 = _mm_cvtsi128_si32(
                                      _mm_or_si128(
                                        _mm_andnot_si128(v22, v21),
                                        _mm_and_si128(v22, _mm_andnot_si128(v21, (__m128i)xmmword_1400033F0))));
                            }
                            v14 = v2
                                + v20
                                * _mm_cvtsi128_si32(_mm_shuffle_epi32(_mm_cvtsi32_si128(v16 + (int)v2
                                                                                            * ((int)v15++ + 321)), 0));
                          }
                          while ( v15 < (unsigned __int64)v5 );
                          v6 = (int *)v4[6];
                          v3 = qword_140005698;
                        }
                        if ( v3 == v14 )
                          break;
                        if ( ++v11 >= v12 )
                          goto LABEL_29;
                      }
                      v23 = (__int64)v6 + *(unsigned int *)(v10 + 4i64 * *(unsigned __int16 *)(v29 + 2 * v11));
                      if ( v23 )
                        goto LABEL_32;
LABEL_29:
                      v2 = 523i64;
                      v5 = v28;
                    }
                  }
                }
              }
              v4 = (PVOID *)*v4;
            }
            while ( v4 != v5 );
          }
          v23 = v27;
LABEL_32:
          qword_140005690 = v23;
          Init_thread_footer(&dword_140005684, v5, v2);
          v1 = v30;
        }
      }
      if ( dword_140005688 > *v1 )
      {
        Init_thread_header(&dword_140005688);
        if ( dword_140005688 == -1 )
        {
          v25 = qword_140005690;
          if ( qword_140005690 )
            v25 = *(_DWORD *)(qword_140005690 + 4);
          dword_1400056A0 = v25;
          Init_thread_footer(&dword_140005688, v24, v2);
        }
      }
      HIDWORD(qword_140005698) = dword_1400056A0;
      Init_thread_footer(&dword_14000568C, (unsigned int)dword_1400056A0, v2);
    }
  }
  if ( HIDWORD(qword_140005698) )
    result = sub_1400015D0(-1, 5125, 0, 0, HIDWORD(qword_140005698));  // syscall function
  else
    result = 0i64;
  return result;
```

## Thanks to
invers1on :heart:, metafaze :heart:
