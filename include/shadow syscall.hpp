// [FAQ] here: https://github.com/annihilatorq/shadow_syscall

// Creator Discord - @ntraiseharderror, Telegram - https://t.me/ntraiseharderror, Github - https://github.com/annihilatorq.
// Special thanks to @invers1on and @metafaze :-)

/*
*  This repository was created to make it easy to use the "syscall"
*  calling technique on Windows operating systems. As of 23.08.2023,
*  only x64 bit programs are supported. Each call is cached and when
*  calling the same syscall repeatedly, you will not have to search
*  again for the desired export in the list of modules and their exports.
*  To disable this feature, apply #define SHADOWSYSCALL_NO_CACHING,
*  but you should realize that the speed of repeated calls will slow
*  down considerably.
*/

#ifndef _SHADOW_SYSCALLS_
#define _SHADOW_SYSCALLS_

#include <cstdint>
#include <intrin.h>
#include <string>
#include <map>

#ifndef SHADOWSYSCALL_NO_FORCEINLINE
#if defined(_MSC_VER)
#define SHADOWSYSCALL_FORCEINLINE __forceinline
#endif
#else
#define SHADOWSYSCALL_FORCEINLINE inline
#endif

#ifndef SHADOWSYSCALL_DISABLE_EXCEPTIONS
#define SHADOWSYSCALL_EXCEPTION_HANDLING true
#else
#define SHADOWSYSCALL_EXCEPTION_HANDLING false
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

#ifndef IMAGE_DOS_SIGNATURE
#define IMAGE_DOS_SIGNATURE	  0x5A4D
#endif

#ifndef IMAGE_NT_OPTIONAL_HDR64_MAGIC
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC   0x20b
#endif

#define HASH_SEED (__TIME__[1] + __TIME__[2] + \
                __TIME__[3] + __TIME__[4] + \
                __TIME__[5] + __TIME__[7] + \
                __TIME__[8])

#define hash_ct_shadowsyscall(str) []() { constexpr shadow_syscall::hash::hash32_t hash { shadow_syscall::hash::FNV1a::get_ct(str, HASH_SEED) }; return hash; }()

#define hash_rt_shadowsyscall(str) shadow_syscall::hash::FNV1a::get_rt(str, HASH_SEED)

#define shadowsyscall(type, export_name, ...) [&]() { constexpr shadow_syscall::hash::hash32_t hash { shadow_syscall::hash::FNV1a::get_ct(#export_name, HASH_SEED) }; \
		return shadow_syscall::invoke::shadow_syscall_create<type>(hash, __VA_ARGS__); }()

namespace shadow_syscall {
	namespace nt {
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

	namespace math
	{
		class intrin {
		public:
			static __forceinline std::int32_t _xor_(
				std::int32_t p, std::int32_t q) noexcept(true)
			{
				if (p == q) return 0;

				return _mm_cvtsi128_si32(_mm_or_si128(_mm_andnot_si128(_mm_cvtsi32_si128(p), _mm_cvtsi32_si128(q)),
					_mm_and_si128(_mm_cvtsi32_si128(p), _mm_andnot_si128(_mm_cvtsi32_si128(q), _mm_set1_epi32(-1)))));
			}

			static __forceinline std::int32_t _add_(
				std::int32_t p, std::int32_t q) noexcept(true)
			{
				return _mm_cvtsi128_si32(_mm_add_epi32(_mm_set1_epi32(p), _mm_set1_epi32(q)));
			}
		};
	}

	namespace hash
	{
		using hash32_t = uint32_t;

		class FNV1a
		{
		private:
			enum : uint32_t
			{
				PRIME = 0x41832u,
				BASIS = 0x83127328u
			};

			static __forceinline constexpr size_t ct_strlen(const char* str, bool include_nullchar = false) noexcept(true)
			{
				size_t out{};

				while (str[++out] != '\0');

				if (include_nullchar)
					++out;

				return out;
			}

		public:
			static __forceinline SHADOWSYSCALL_CONSTEVAL hash32_t get_ct(const char* str, const size_t counter) noexcept(true)
			{
				hash32_t out{ BASIS };
				size_t   len{ ct_strlen(str) };

				for (size_t i{}; i < len; ++i)
					out = str[i] + ((out ^ str[i]) + (counter + i) * str[i]) * (PRIME ^ (i == 0 ? counter : i));

				return out;
			}

			static __forceinline const hash32_t get_rt(const char* str, size_t counter) noexcept(true)
			{
				hash32_t out{ BASIS };
				size_t   len{ ct_strlen(str) };
#ifndef SHADOWSYSCALL_DISABLE_INTRIN_HASH
				for (size_t i {}; i < len; ++i)
					out = str[i] + math::intrin::_add_(math::intrin::_xor_(out, str[i]), (counter + i) * str[i]) *
					(math::intrin::_xor_(PRIME, (i == 0 ? counter : i)));
#else
				for (size_t i{}; i < len; ++i)
					out = str[i] + ((out ^ str[i]) + (counter + i) * str[i]) * (PRIME ^ (i == 0 ? counter : i));
#endif
				return out;
			}
		};
	}

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

		SHADOWSYSCALL_FORCEINLINE const ::shadow_syscall::nt::PEB* get_ppeb() noexcept(true)
		{
			return reinterpret_cast<::shadow_syscall::nt::PEB*>(__readgsqword(0x60));
		}

		SHADOWSYSCALL_FORCEINLINE const ::shadow_syscall::nt::PIMAGE_NT_HEADERS64 nt_header(
			uintptr_t module_base) noexcept(true)
		{
			return reinterpret_cast<::shadow_syscall::nt::PIMAGE_NT_HEADERS64>(module_base + reinterpret_cast<const ::shadow_syscall::nt::IMAGE_DOS_HEADER*>(module_base)->e_lfanew);
		}

		SHADOWSYSCALL_FORCEINLINE const ::shadow_syscall::nt::IMAGE_DOS_HEADER* dos_header(
			uintptr_t module_base) noexcept(true)
		{
			return reinterpret_cast<::shadow_syscall::nt::IMAGE_DOS_HEADER*>(module_base);
		}

		SHADOWSYSCALL_FORCEINLINE const ::shadow_syscall::nt::PIMAGE_OPTIONAL_HEADER64 optional_header(
			uintptr_t module_base) noexcept(true)
		{
			return &nt_header(module_base)->OptionalHeader;
		}

		SHADOWSYSCALL_FORCEINLINE const bool dos_header_empty(
			uintptr_t module_base) noexcept(true)
		{
			return optional_header(module_base)->DataDirectory[0].Size <= 0ul;
		}

		SHADOWSYSCALL_FORCEINLINE const ::shadow_syscall::nt::PIMAGE_EXPORT_DIRECTORY image_export_dir(
			uintptr_t module_base) noexcept(true)
		{
			return reinterpret_cast<::shadow_syscall::nt::PIMAGE_EXPORT_DIRECTORY>(module_base +
				optional_header(module_base)->DataDirectory[0].VirtualAddress);
		}

		SHADOWSYSCALL_FORCEINLINE const uintptr_t dll_base(
			::shadow_syscall::nt::_LDR_DATA_TABLE_ENTRY* table_entry) noexcept(true)
		{
			return reinterpret_cast<uintptr_t>(table_entry->DllBase);
		}

		SHADOWSYSCALL_FORCEINLINE const ::shadow_syscall::nt::PEB_LDR_DATA* loader_data()
		{
			return reinterpret_cast<const ::shadow_syscall::nt::PEB_LDR_DATA*>(get_ppeb()->LoaderData);
		}

		SHADOWSYSCALL_FORCEINLINE const ::shadow_syscall::nt::LDR_DATA_TABLE_ENTRY* ldr_data_entry() noexcept(true)
		{
			return reinterpret_cast<const ::shadow_syscall::nt::LDR_DATA_TABLE_ENTRY*>(loader_data()->InLoadOrderModuleList.Flink);
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
		static SHADOWSYSCALL_FORCEINLINE _Type module_export(
			uintptr_t module_base, uint32_t export_hash) noexcept(SHADOWSYSCALL_EXCEPTION_HANDLING)
		{
			if (::shadow_syscall::utils::dos_header(module_base)->e_magic != IMAGE_DOS_SIGNATURE)
			{
#ifndef SHADOWSYSCALL_DISABLE_EXCEPTIONS
				throw std::runtime_error("DOS header e_magic mismatch");
#else
				return 0;
#endif
			}

			if (::shadow_syscall::utils::nt_header(module_base)->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
			{
				if (::shadow_syscall::utils::dos_header_empty(module_base))
				{
					return 0;
				}
			}

			uint32_t* rva_names = reinterpret_cast<uint32_t*>(module_base + ::shadow_syscall::utils::image_export_dir(module_base)->AddressOfNames);
			uint32_t* function_rva = reinterpret_cast<uint32_t*>(module_base + ::shadow_syscall::utils::image_export_dir(module_base)->AddressOfFunctions);
			uint16_t* ordinal_names = reinterpret_cast<uint16_t*>(module_base + ::shadow_syscall::utils::image_export_dir(module_base)->AddressOfNameOrdinals);

			for (size_t i {}; i < ::shadow_syscall::utils::image_export_dir(module_base)->NumberOfNames; ++i)
			{
				const auto export_name = (const char*)(module_base + rva_names[i]);

				if (export_hash == ::shadow_syscall::hash::FNV1a::get_rt(export_name, HASH_SEED))
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
		SHADOWSYSCALL_FORCEINLINE _Type get_export_by_hash(uint32_t export_hash) noexcept(SHADOWSYSCALL_EXCEPTION_HANDLING)
		{
			const auto list_header = &::shadow_syscall::utils::loader_data()->InLoadOrderModuleList;

			for (auto iterator = list_header->Flink; iterator != list_header; iterator = iterator->Flink)
			{
				::shadow_syscall::nt::_LDR_DATA_TABLE_ENTRY* entry = CONTAINING_RECORD(iterator,
					::shadow_syscall::nt::LDR_DATA_TABLE_ENTRY,
					InLoadOrderLinks);

				if (!entry->BaseDllName.Buffer)
					continue;

				const auto export_address = ::shadow_syscall::detail::module_export<uintptr_t>(::shadow_syscall::utils::dll_base(entry), export_hash);

				if (!export_address)
					continue;

				return static_cast<_Type>(export_address);
			}
		}

		SHADOWSYSCALL_FORCEINLINE std::int32_t get_syscall_id_from_export_address(
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

			return *reinterpret_cast<std::int32_t*>(static_cast<uintptr_t>(address_of_export + 4));
		}
	}

	namespace masm
	{
		extern "C" void* asm_syscall();
	}

	namespace internals
	{
		class shadowsyscall_internals
		{
		public:
			SHADOWSYSCALL_FORCEINLINE shadowsyscall_internals(uint32_t export_hash) noexcept(false) : syscall_export_hash(export_hash)
			{
#ifndef SHADOWSYSCALL_NO_CACHING
				if (::shadow_syscall::utils::map_element_exists<uintptr_t, int32_t>(
					this->cached_calls, this->syscall_export_hash))
				{
					this->syscall_idx = cached_calls.at(this->syscall_export_hash);
					return;
				}
#endif

				auto export_addr = ::shadow_syscall::detail::get_export_by_hash<uintptr_t>(this->syscall_export_hash);
				auto sys_index = ::shadow_syscall::detail::get_syscall_id_from_export_address(export_addr);

				this->syscall_idx = sys_index;

#ifndef SHADOWSYSCALL_NO_CACHING
				cached_calls.insert({ this->syscall_export_hash, this->syscall_idx });
#endif
			}

			template<class _Type, class... _Args>
			SHADOWSYSCALL_FORCEINLINE _Type create_shadow_syscall(_Args... args) noexcept(true)
			{
				using arg_mapper = remap_args<sizeof...(_Args), void>;
				return (_Type)arg_mapper::create_call(this->syscall_idx, args...);
			}

			SHADOWSYSCALL_FORCEINLINE bool validate_syscall_index()
			{
				return this->syscall_idx != 0;
			}

		private:
			template <class... _Args>
			static SHADOWSYSCALL_FORCEINLINE auto syscall_redirection(
				_Args... args) -> void*
			{
				using pack_args = void*(__stdcall*)(_Args...);
				auto fn = reinterpret_cast<pack_args>(&::shadow_syscall::masm::asm_syscall);
				return fn(args...);
			}

			template <size_t argc, class enable_if>
			struct remap_args
			{
				template<class _Type1, class _Type2, class _Type3, class _Type4, class... _Args>
				static SHADOWSYSCALL_FORCEINLINE void* create_call(
					std::uint32_t syscall_index, _Type1 _first, _Type2 _second, _Type3 _third, _Type4 _fourth, _Args... _args)
				{
					return syscall_redirection(_first, _second, _third, _fourth, syscall_index, nullptr, _args...);
				}
			};

			template <size_t argc>
			struct remap_args<argc, std::enable_if_t<argc <= 4>>
			{
				template<class _Type1 = void*, class _Type2 = void*, class _Type3 = void*, class _Type4 = void*>
				static SHADOWSYSCALL_FORCEINLINE void* create_call(
					std::uint32_t syscall_index, _Type1 _first = _Type1{}, _Type2 _second = _Type2{}, _Type3 _third = _Type3{}, _Type4 _fourth = _Type4{})
				{
					return syscall_redirection(_first, _second, _third, _fourth, syscall_index, nullptr);
				}
			};

			uintptr_t syscall_export_hash = 0;
			int32_t syscall_idx = 0;

#ifndef SHADOWSYSCALL_NO_CACHING
			static inline std::map<uintptr_t, int32_t> cached_calls {};
#endif
		};
	}

	namespace invoke
	{
		template<class _Type, class... Args>
		SHADOWSYSCALL_FORCEINLINE _Type shadow_syscall_create(std::uint32_t export_hash, Args... arguments) noexcept(SHADOWSYSCALL_EXCEPTION_HANDLING)
		{
			auto syscall_internal = ::shadow_syscall::internals::shadowsyscall_internals(export_hash);

			if (!syscall_internal.validate_syscall_index())
			{
#ifndef SHADOWSYSCALL_DISABLE_EXCEPTIONS
				throw std::runtime_error("Syscall index is null");
#else
				return 0;
#endif
			}

			return syscall_internal.create_shadow_syscall<_Type>(arguments...);
		}
	}
}

#endif
