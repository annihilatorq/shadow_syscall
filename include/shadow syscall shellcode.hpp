// [FAQ] here: https://github.com/annihilatorq/shadow_syscall

// Creator Discord - @ntraiseharderror, Telegram - https://t.me/ntraiseharderror, Github - https://github.com/annihilatorq.
// Special thanks to @invers1on

#ifndef _SHADOW_SYSCALLS_SHELLCODE_
#define _SHADOW_SYSCALLS_SHELLCODE_

#include <Windows.h>
#include <cstdint>
#include <intrin.h>
#include <string>
#include <vector>
#include <map>

#ifndef SHADOWSYSCALL_NO_FORCEINLINE
#if defined(_MSC_VER)
#define SHADOWSYSCALL_FORCEINLINE __forceinline
#endif
#else
#define SHADOWSYSCALL_FORCEINLINE inline
#endif

#ifndef SHADOWSYSCALL_DISABLE_EXCEPTIONS
#include <stdexcept>
#define SHADOWSYSCALL_EXCEPTION_HANDLING false
#else
#define SHADOWSYSCALL_EXCEPTION_HANDLING true
#endif

#if _HAS_CXX20
#define SHADOWSYSCALL_CONSTEVAL consteval
#else
#define SHADOWSYSCALL_CONSTEVAL constexpr
#endif

#ifndef CONTAINING_RECORD
#define CONTAINING_RECORD(address, type, field) ((type *)( \
                                                  (char*)(address) - \
                                                  (unsigned long long)(&((type *)0)->field)))
#endif

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#ifndef IMAGE_DOS_SIGNATURE
#define IMAGE_DOS_SIGNATURE	  0x5A4D
#endif

#ifndef IMAGE_NT_OPTIONAL_HDR64_MAGIC
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC   0x20b
#endif

#define HASH_SEED 1209689126

#define shadowsyscall_hashct(str) []() { constexpr uint32_t hash { shadow_syscall::FNV1a::compiletime_hash(str, HASH_SEED) }; return hash; }()
#define shadowsyscall_hashrt(str) shadow_syscall::FNV1a::runtime_hash(str, HASH_SEED)

#define shadowsyscall(type, export_name) [&]() { constexpr uint32_t hash { shadow_syscall::FNV1a::compiletime_hash(#export_name, HASH_SEED) }; \
		return ::shadow_syscall::internals::shadowsyscall_internals<type>(hash); }()

#define shadowsyscall_(type, export_name, ...) [&]() { return shadowsyscall(type, export_name).invoke(__VA_ARGS__); }()

namespace shadow_syscall {
	namespace PE {
		struct UNICODE_STRING {
			unsigned short  Length;
			unsigned short  MaximumLength;
			wchar_t* Buffer;
		};

		typedef struct _LIST_ENTRY {
			struct _LIST_ENTRY* Flink;
			struct _LIST_ENTRY* Blink;
		} LIST_ENTRY, * PLIST_ENTRY, * PRLIST_ENTRY;

		typedef struct _LDR_DATA_TABLE_ENTRY {
			LIST_ENTRY InLoadOrderLinks;
			LIST_ENTRY InMemoryOrderLinks;
			void* Reserved2[2];
			void* DllBase;
			void* EntryPoint;
			void* Reserved3;
			UNICODE_STRING FullDllName;
			UNICODE_STRING BaseDllName;
			void* Reserved5[3];
			union {
				unsigned long CheckSum;
				void* Reserved6;
			};
			unsigned long          TimeDateStamp;
		} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

		typedef struct _PEB_LDR_DATA {
			unsigned long Length;
			unsigned char Initialized;
			void* SsHandle;
			LIST_ENTRY InLoadOrderModuleList;
			LIST_ENTRY InMemoryOrderModuleList;
			LIST_ENTRY InInitializationOrderModuleList;
		} PEB_LDR_DATA, * PPEB_LDR_DATA;

		typedef struct _PEB {
			unsigned char InheritedAddressSpace;
			unsigned char ReadImageFileExecOptions;
			unsigned char BeingDebugged;
			unsigned char Spare;
			void* Mutant;
			void* ImageBaseAddress;
			PPEB_LDR_DATA LoaderData;
			void* SubSystemData;
			void* ProcessHeap;
			void* FastPebLock;
			unsigned long long FastPebLockRoutine;
			unsigned long long FastPebUnlockRoutine;
			unsigned long EnvironmentUpdateCount;
			unsigned long long KernelCallbackTable;
			void* EventLogSection;
			void* EventLog;
			unsigned long TlsExpansionCounter;
			void* TlsBitmap;
			unsigned long TlsBitmapBits[0x2];
			void* ReadOnlySharedMemoryBase;
			void* ReadOnlySharedMemoryHeap;
			unsigned long long ReadOnlyStaticServerData;
			void* AnsiCodePageData;
			void* OemCodePageData;
			void* UnicodeCaseTableData;
			unsigned long NumberOfProcessors;
			unsigned long NtGlobalFlag;
			unsigned char Spare2[0x4];
			unsigned long HeapSegmentReserve;
			unsigned long HeapSegmentCommit;
			unsigned long HeapDeCommitTotalFreeThreshold;
			unsigned long HeapDeCommitFreeBlockThreshold;
			unsigned long NumberOfHeaps;
			unsigned long MaximumNumberOfHeaps;
			unsigned long long* ProcessHeaps;
			void* GdiSharedHandleTable;
			void* ProcessStarterHelper;
			void* GdiDCAttributeList;
			void* LoaderLock;
			unsigned long OSMajorVersion;
			unsigned long OSMinorVersion;
			unsigned long OSBuildNumber;
			unsigned long OSPlatformId;
			unsigned long ImageSubSystem;
			unsigned long ImageSubSystemMajorVersion;
			unsigned long ImageSubSystemMinorVersion;
			unsigned long GdiHandleBuffer[0x22];
			unsigned long PostProcessInitRoutine;
			unsigned long TlsExpansionBitmap;
			unsigned char TlsExpansionBitmapBits[0x80];
			unsigned long SessionId;
		} PEB, * PPEB;

		typedef struct _IMAGE_EXPORT_DIRECTORY {
			unsigned long  Characteristics;
			unsigned long  TimeDateStamp;
			unsigned short MajorVersion;
			unsigned short MinorVersion;
			unsigned long  Name;
			unsigned long  Base;
			unsigned long  NumberOfFunctions;
			unsigned long  NumberOfNames;
			unsigned long  AddressOfFunctions; // RVA from base of image
			unsigned long  AddressOfNames; // RVA from base of image
			unsigned long  AddressOfNameOrdinals; // RVA from base of image
		} IMAGE_EXPORT_DIRECTORY, * PIMAGE_EXPORT_DIRECTORY;

		struct IMAGE_DOS_HEADER { // DOS .EXE header
			unsigned short e_magic; // Magic number
			unsigned short e_cblp; // Bytes on last page of file
			unsigned short e_cp; // Pages in file
			unsigned short e_crlc; // Relocations
			unsigned short e_cparhdr; // Size of header in paragraphs
			unsigned short e_minalloc; // Minimum extra paragraphs needed
			unsigned short e_maxalloc; // Maximum extra paragraphs needed
			unsigned short e_ss; // Initial (relative) SS value
			unsigned short e_sp; // Initial SP value
			unsigned short e_csum; // Checksum
			unsigned short e_ip; // Initial IP value
			unsigned short e_cs; // Initial (relative) CS value
			unsigned short e_lfarlc; // File address of relocation table
			unsigned short e_ovno; // Overlay number
			unsigned short e_res[4]; // Reserved words
			unsigned short e_oemid; // OEM identifier (for e_oeminfo)
			unsigned short e_oeminfo; // OEM information; e_oemid specific
			unsigned short e_res2[10]; // Reserved words
			long           e_lfanew; // File address of new exe header
		};

		struct IMAGE_FILE_HEADER {
			unsigned short Machine;
			unsigned short NumberOfSections;
			unsigned long  TimeDateStamp;
			unsigned long  PointerToSymbolTable;
			unsigned long  NumberOfSymbols;
			unsigned short SizeOfOptionalHeader;
			unsigned short Characteristics;
		};

		struct IMAGE_DATA_DIRECTORY {
			unsigned long VirtualAddress;
			unsigned long Size;
		};

		typedef struct _IMAGE_OPTIONAL_HEADER64 {
			unsigned short Magic;
			unsigned char MajorLinkerVersion;
			unsigned char MinorLinkerVersion;
			unsigned long SizeOfCode;
			unsigned long SizeOfInitializedData;
			unsigned long SizeOfUninitializedData;
			unsigned long AddressOfEntryPoint;
			unsigned long BaseOfCode;
			unsigned long long ImageBase;
			unsigned long SectionAlignment;
			unsigned long FileAlignment;
			unsigned short MajorOperatingSystemVersion;
			unsigned short MinorOperatingSystemVersion;
			unsigned short MajorImageVersion;
			unsigned short MinorImageVersion;
			unsigned short MajorSubsystemVersion;
			unsigned short MinorSubsystemVersion;
			unsigned long Win32VersionValue;
			unsigned long SizeOfImage;
			unsigned long SizeOfHeaders;
			unsigned long CheckSum;
			unsigned short Subsystem;
			unsigned short DllCharacteristics;
			unsigned long long SizeOfStackReserve;
			unsigned long long SizeOfStackCommit;
			unsigned long long SizeOfHeapReserve;
			unsigned long long SizeOfHeapCommit;
			unsigned long LoaderFlags;
			unsigned long NumberOfRvaAndSizes;
			IMAGE_DATA_DIRECTORY DataDirectory[16];
		} IMAGE_OPTIONAL_HEADER64, * PIMAGE_OPTIONAL_HEADER64;

		typedef struct _IMAGE_NT_HEADERS64 {
			unsigned long Signature;
			IMAGE_FILE_HEADER FileHeader;
			IMAGE_OPTIONAL_HEADER64 OptionalHeader;
		} IMAGE_NT_HEADERS64, * PIMAGE_NT_HEADERS64;
	}

#ifndef SHADOWSYSCALL_DISABLE_INTRIN_HASH
	namespace math
	{
		static SHADOWSYSCALL_FORCEINLINE std::int32_t _xor_(
			std::int32_t p, std::int32_t q) noexcept(true)
		{
			if (p == q) return 0;

#ifndef SHADOWSYSCALL_USE_AVX_INTRINS
			return _mm_cvtsi128_si32(_mm_or_si128(_mm_andnot_si128(_mm_cvtsi32_si128(p), _mm_cvtsi32_si128(q)),
				_mm_and_si128(_mm_cvtsi32_si128(p), _mm_andnot_si128(_mm_cvtsi32_si128(q), _mm_set1_epi32(-1)))));
#else
			return _mm_cvtsi128_si32(_mm256_castsi256_si128(_mm256_or_si256(_mm256_andnot_si256(_mm256_set1_epi32(p),
				_mm256_set1_epi32(q)), _mm256_andnot_si256(_mm256_set1_epi32(q), _mm256_set1_epi32(p)))));
#endif
		}

		static SHADOWSYSCALL_FORCEINLINE std::int32_t _add_(
			std::int32_t p, std::int32_t q) noexcept(true)
		{
#ifndef SHADOWSYSCALL_USE_AVX_INTRINS
			return _mm_cvtsi128_si32(_mm_add_epi32(_mm_set1_epi32(p), _mm_set1_epi32(q)));
#else
			return _mm_cvtsi128_si32(_mm256_castsi256_si128(_mm256_add_epi32(_mm256_set1_epi32(p), _mm256_set1_epi32(q))));
#endif
		}
	}
#endif


	class FNV1a
	{
	private:
		enum : uint32_t
		{
			PRIME = 0x41832u,
			BASIS = 0x83127328u
		};

		static SHADOWSYSCALL_FORCEINLINE constexpr size_t compiletime_strlen(const char* str, bool include_nullchar = false) noexcept(true)
		{
			size_t out{};

			while (str[++out] != '\0');

			if (include_nullchar)
				++out;

			return out;
		}

	public:
		static SHADOWSYSCALL_FORCEINLINE SHADOWSYSCALL_CONSTEVAL uint32_t compiletime_hash(const char* str, const size_t counter) noexcept(true)
		{
			uint32_t out{ BASIS };
			size_t   len{ compiletime_strlen(str) };

			for (size_t i{}; i < len; ++i)
				out = str[i] + ((out ^ str[i]) + (counter + i) * str[i]) * (PRIME ^ (i == 0 ? counter : i));

			return out;
		}

		static SHADOWSYSCALL_FORCEINLINE const uint32_t runtime_hash(const char* str, size_t counter) noexcept(true)
		{
			uint32_t out{ BASIS };
			size_t   len{ compiletime_strlen(str) };
#ifndef SHADOWSYSCALL_DISABLE_INTRIN_HASH
			for (size_t i{}; i < len; ++i)
				out = str[i] + math::_add_(math::_xor_(out, str[i]), (counter + i) * str[i]) *
				(math::_xor_(PRIME, (i == 0 ? counter : i)));
#else
			for (size_t i{}; i < len; ++i)
				out = str[i] + ((out ^ str[i]) + (counter + i) * str[i]) * (PRIME ^ (i == 0 ? counter : i));
#endif
			return out;
		}
	};
	

	namespace utils
	{
		SHADOWSYSCALL_FORCEINLINE std::string wide_to_string(
			wchar_t* buffer) noexcept(true)
		{
			const std::wstring out(buffer);

			if (out.empty())
				return "";

			return std::string(out.begin(), out.end());
		}

		SHADOWSYSCALL_FORCEINLINE void* memcpy(void* _Destination, const void* _Source, size_t n) 
		{
			char* d = static_cast<char*>(_Destination);
			const char* s = const_cast<char*>(static_cast<const char*>(_Source));

			for (size_t i {}; i < n; ++i)
			{
				d[i] = s[i];
			}

			return _Destination;
		}

		SHADOWSYSCALL_FORCEINLINE const ::shadow_syscall::PE::PEB* get_ppeb() noexcept(true)
		{
			return reinterpret_cast<::shadow_syscall::PE::PEB*>(__readgsqword(0x60));
		}

		SHADOWSYSCALL_FORCEINLINE const ::shadow_syscall::PE::PIMAGE_NT_HEADERS64 nt_header(
			uintptr_t module_base) noexcept(true)
		{
			return reinterpret_cast<::shadow_syscall::PE::PIMAGE_NT_HEADERS64>(module_base + reinterpret_cast<const ::shadow_syscall::PE::IMAGE_DOS_HEADER*>(module_base)->e_lfanew);
		}

		SHADOWSYSCALL_FORCEINLINE const ::shadow_syscall::PE::IMAGE_DOS_HEADER* dos_header(
			uintptr_t module_base) noexcept(true)
		{
			return reinterpret_cast<::shadow_syscall::PE::IMAGE_DOS_HEADER*>(module_base);
		}

		SHADOWSYSCALL_FORCEINLINE const ::shadow_syscall::PE::PIMAGE_OPTIONAL_HEADER64 optional_header(
			uintptr_t module_base) noexcept(true)
		{
			return &nt_header(module_base)->OptionalHeader;
		}

		SHADOWSYSCALL_FORCEINLINE const bool dos_header_empty(
			uintptr_t module_base) noexcept(true)
		{
			return optional_header(module_base)->DataDirectory[0].Size <= 0ul;
		}

		SHADOWSYSCALL_FORCEINLINE const ::shadow_syscall::PE::PIMAGE_EXPORT_DIRECTORY image_export_dir(
			uintptr_t module_base) noexcept(true)
		{
			return reinterpret_cast<::shadow_syscall::PE::PIMAGE_EXPORT_DIRECTORY>(module_base +
				optional_header(module_base)->DataDirectory[0].VirtualAddress);
		}

		SHADOWSYSCALL_FORCEINLINE const uintptr_t dll_base(
			::shadow_syscall::PE::_LDR_DATA_TABLE_ENTRY* table_entry) noexcept(true)
		{
			return reinterpret_cast<uintptr_t>(table_entry->DllBase);
		}

		SHADOWSYSCALL_FORCEINLINE const ::shadow_syscall::PE::PEB_LDR_DATA* loader_data() noexcept(true)
		{
			return reinterpret_cast<const ::shadow_syscall::PE::PEB_LDR_DATA*>(get_ppeb()->LoaderData);
		}

		SHADOWSYSCALL_FORCEINLINE const ::shadow_syscall::PE::LDR_DATA_TABLE_ENTRY* ldr_data_entry() noexcept(true)
		{
			return reinterpret_cast<const ::shadow_syscall::PE::LDR_DATA_TABLE_ENTRY*>(loader_data()->InLoadOrderModuleList.Flink);
		}

		template <class _Type1, class _Type2>
		SHADOWSYSCALL_FORCEINLINE const bool map_element_exists(
			std::map<_Type1, _Type2> _map, _Type1 _key) noexcept(true)
		{
			return (_map.find(_key) != _map.end());
		}
	}

	namespace detail
	{
		template<class _Type>
		_Type module_export(uintptr_t module_base, uint32_t export_hash) noexcept(SHADOWSYSCALL_EXCEPTION_HANDLING)
		{
			if (::shadow_syscall::utils::dos_header(module_base)->e_magic != IMAGE_DOS_SIGNATURE)
			{
#ifndef SHADOWSYSCALL_DISABLE_EXCEPTIONS
				throw std::runtime_error("DOS header e_magic mismatch");
#else
				return 0;
#endif
			}

			if (::shadow_syscall::utils::nt_header(module_base)->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC &&
				::shadow_syscall::utils::dos_header_empty(module_base))
			{
				return 0;
			}

			uint32_t* rva_names = reinterpret_cast<uint32_t*>(module_base + ::shadow_syscall::utils::image_export_dir(module_base)->AddressOfNames);
			uint32_t* function_rva = reinterpret_cast<uint32_t*>(module_base + ::shadow_syscall::utils::image_export_dir(module_base)->AddressOfFunctions);
			uint16_t* ordinal_names = reinterpret_cast<uint16_t*>(module_base + ::shadow_syscall::utils::image_export_dir(module_base)->AddressOfNameOrdinals);

			for (size_t i {}; i < ::shadow_syscall::utils::image_export_dir(module_base)->NumberOfNames; ++i)
			{
				const auto export_name = (const char*)(module_base + rva_names[i]);

				if (export_hash == ::shadow_syscall::FNV1a::runtime_hash(export_name, HASH_SEED))
				{
					return static_cast<_Type>(module_base + function_rva[ordinal_names[i]]);
				}
			}
#ifndef SHADOWSYSCALL_DISABLE_EXCEPTIONS
			throw std::runtime_error("Can't find desired export");
#else
			return 0;
#endif
		}

		template<class _Type>
		_Type get_export_by_hash(uint32_t export_hash) noexcept(SHADOWSYSCALL_EXCEPTION_HANDLING)
		{
			const auto list_header = &::shadow_syscall::utils::loader_data()->InLoadOrderModuleList;

			for (auto iterator = list_header->Flink; iterator != list_header; iterator = iterator->Flink)
			{
				::shadow_syscall::PE::_LDR_DATA_TABLE_ENTRY* entry = CONTAINING_RECORD(iterator,
					::shadow_syscall::PE::LDR_DATA_TABLE_ENTRY,
					InLoadOrderLinks);

				if (!entry->BaseDllName.Buffer)
					continue;

				const auto export_address = ::shadow_syscall::detail::module_export<uintptr_t>(::shadow_syscall::utils::dll_base(entry), export_hash);

				if (!export_address)
					continue;

				return static_cast<_Type>(export_address);
			}
		}

		SHADOWSYSCALL_FORCEINLINE std::uint32_t get_syscall_id_from_export_address(
			uintptr_t address_of_export) noexcept(SHADOWSYSCALL_EXCEPTION_HANDLING)
		{
			if (!address_of_export)
			{
#ifndef SHADOWSYSCALL_DISABLE_EXCEPTIONS
				throw std::invalid_argument("Address of export shouldn't be null");
#else
				return 0;
#endif
			}

			return *reinterpret_cast<std::uint32_t*>(static_cast<uintptr_t>(address_of_export + 4));
		}
	}

	namespace internals
	{
		LPVOID NtVirtualAlloc(uintptr_t NtAllocateVirtualMemoryAddr, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)
		{
			PVOID BaseAddress = lpAddress;
			ULONG_PTR RegionSize = dwSize;
			
			NTSTATUS Result = reinterpret_cast<NTSTATUS(__stdcall*)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG)>
				(NtAllocateVirtualMemoryAddr)(
				(HANDLE)-1,
				&BaseAddress,
				0,
				&RegionSize,
				flAllocationType & 0xFFFFFFC0,
				flProtect);

			if (NT_SUCCESS(Result))
				return BaseAddress;

			return nullptr;
		}

		BOOL NtVirtualFree(uintptr_t NtFreeVirtualMemoryAddr, LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType)
		{
			NTSTATUS Result = 0;
			ULONG_PTR RegionSize = dwSize;
			PVOID BaseAddress = lpAddress;

			if ((dwFreeType & 0xFFFF3FFC) != 0 || (dwFreeType & 0x8003) == 0x8000 && dwSize)
			{
				Result = -0x3FFFFFF3;
			}

			Result = reinterpret_cast<NTSTATUS(__stdcall*)(HANDLE, PVOID*, PSIZE_T, ULONG)>(NtFreeVirtualMemoryAddr)(
				(HANDLE)-1, &BaseAddress, &RegionSize, dwFreeType);

			if (Result == -0x3FFFFFBB)
			{
				Result = reinterpret_cast<NTSTATUS(__stdcall*)(HANDLE, PVOID*, PSIZE_T, ULONG)>(NtFreeVirtualMemoryAddr)(
					(HANDLE)-1, &BaseAddress, &RegionSize, dwFreeType);
			}

			return NT_SUCCESS(Result);
		}

		class shellcode_allocator
		{
		public:
			SHADOWSYSCALL_FORCEINLINE shellcode_allocator(std::initializer_list<uint8_t> list) : shellcode(list.begin(), list.end()) {}

			SHADOWSYSCALL_FORCEINLINE void allocate_memory(uintptr_t virtualAllocAddr)
			{
				this->memory = NtVirtualAlloc(virtualAllocAddr, nullptr, shellcode.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

				if (this->memory == nullptr)
				{
#ifndef SHADOWSYSCALL_DISABLE_EXCEPTIONS
					throw std::runtime_error("Can't allocate virtual memory");
#else
					return;
#endif		
				}

				utils::memcpy(this->memory, shellcode.data(), shellcode.size());
				*reinterpret_cast<void**>(&this->shellcode_fn) = this->memory;
			}

			SHADOWSYSCALL_FORCEINLINE void deallocate_memory(uintptr_t virtualFreeAddr)
			{
				if (this->memory != nullptr) {
					NtVirtualFree(virtualFreeAddr, this->memory, 0, MEM_RELEASE);
					this->memory = nullptr;
				}
			}

			SHADOWSYSCALL_FORCEINLINE void set_byte(uint32_t index, uint32_t value)
			{
				*reinterpret_cast<uint32_t*>(&shellcode.at(index)) = value;
			}

			SHADOWSYSCALL_FORCEINLINE void* call()
			{
				return shellcode_fn;
			}

		private:
			void* memory = nullptr;
			void* shellcode_fn = nullptr;
			std::vector<uint8_t> shellcode;
		};

		template <class _Type>
		class shadowsyscall_internals
		{
		public:
			SHADOWSYSCALL_FORCEINLINE shadowsyscall_internals(uint32_t export_hash) noexcept(true) : syscall_export_hash(export_hash)
			{
				if (this->virtual_routine_address.first == 0 || virtual_routine_address.second == 0) 
				{
					this->virtual_routine_address.first = ::shadow_syscall::detail::get_export_by_hash<uintptr_t>(shadowsyscall_hashct("NtAllocateVirtualMemory"));
					this->virtual_routine_address.second = ::shadow_syscall::detail::get_export_by_hash<uintptr_t>(shadowsyscall_hashct("NtFreeVirtualMemory"));
				}

#ifndef SHADOWSYSCALL_NO_CACHING
				if (::shadow_syscall::utils::map_element_exists<uint32_t, uint32_t>(
					this->index_map, this->syscall_export_hash))
				{
					this->syscall_idx = index_map.at(this->syscall_export_hash);
					sc_shellcode.set_byte(6, syscall_idx);
					sc_shellcode.allocate_memory(this->virtual_routine_address.first);
					return;
				}
#endif

				find_syscall_index();
			}

			SHADOWSYSCALL_FORCEINLINE ~shadowsyscall_internals()
			{
				sc_shellcode.deallocate_memory(this->virtual_routine_address.second);
			}

			SHADOWSYSCALL_FORCEINLINE uint32_t const syscall_index() noexcept(true)
			{
				return this->syscall_idx;
			}

			SHADOWSYSCALL_FORCEINLINE void find_syscall_index() noexcept(true)
			{
				const auto export_addr = ::shadow_syscall::detail::get_export_by_hash<uintptr_t>(this->syscall_export_hash);
				const auto sys_index = ::shadow_syscall::detail::get_syscall_id_from_export_address(export_addr);

				this->syscall_idx = sys_index;

#ifndef SHADOWSYSCALL_NO_CACHING
				index_map.insert(std::make_pair(this->syscall_export_hash, sys_index));
#endif

				sc_shellcode.set_byte(6, syscall_idx);
				sc_shellcode.allocate_memory(this->virtual_routine_address.first);
			}

			template<class... Args>
			SHADOWSYSCALL_FORCEINLINE _Type invoke(
				Args... arguments) noexcept(true)
			{
				return reinterpret_cast<_Type(__stdcall*)(Args...)>(sc_shellcode.call())(arguments...);
			}

		private:
			uint32_t syscall_export_hash = 0;
			uint32_t syscall_idx = 0;

			shellcode_allocator sc_shellcode =
			{
				0x49, 0x89, 0xCA,                           // mov r10, rcx
				0x48, 0xC7, 0xC0, 0x3F, 0x10, 0x00, 0x00,   // mov rax, syscall_index
				0x0F, 0x05,                                 // syscall
				0xC3                                        // ret
			};

#ifndef SHADOWSYSCALL_NO_CACHING
			static inline std::map<uint32_t, uint32_t> index_map;
#endif
			static inline std::pair<uintptr_t, uintptr_t> virtual_routine_address;
		};
	}
}

#endif // _SHADOW_SYSCALLS_SHELLCODE_
