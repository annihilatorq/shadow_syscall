// [FAQ] here: https://github.com/annihilatorq/shadow_syscall

// Creator Discord - @ntraiseharderror, Telegram - https://t.me/ntraiseharderror, Github - https://github.com/annihilatorq.
// Special thanks to @invers1on

#ifndef SHADOW_SYSCALLS_SHELL_HPP
#define SHADOW_SYSCALLS_SHELL_HPP

#define SHADOWSYSCALL_DISABLE_CACHING

#ifndef _M_X64
#error Currently unsupported target architecture.
#endif

#include <intrin.h>

#ifndef SHADOWSYSCALL_DISABLE_CACHING
#include <unordered_map>
#endif

#ifndef SHADOWSYSCALL_DISABLE_EXCEPTIONS
#define SHADOWSYSCALL_EXCEPTION_HANDLING false
#else
#define SHADOWSYSCALL_EXCEPTION_HANDLING true
#endif

#ifndef SHADOWSYSCALL_NO_FORCEINLINE
#if defined(_MSC_VER)
#define SHADOWSYSCALL_FORCEINLINE __forceinline
#endif
#else
#define SHADOWSYSCALL_FORCEINLINE inline
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
#define NT_SUCCESS(Status) (((long)(Status)) >= 0)
#endif

#ifndef IMAGE_DOS_SIGNATURE
#define IMAGE_DOS_SIGNATURE 0x5A4D
#endif

#ifndef IMAGE_NT_OPTIONAL_HDR_MAGIC
#if defined(_M_X64)
#define IMAGE_NT_OPTIONAL_HDR_MAGIC 0x20b
#elif defined(_M_IX86)
#define IMAGE_NT_OPTIONAL_HDR_MAGIC 0x10b
#endif
#endif

#ifndef SHADOWSYSCALL_CASE_INSENSITIVE
#define SHADOWSYSCALL_CASE_SENSITIVITY true
#else
#define SHADOWSYSCALL_CASE_SENSITIVITY false
#endif

#define SHADOWSYSCALL_TOLOWER(c) ((c >= 'A' && c <= 'Z') ? (c + 32) : c)

#if _HAS_CXX17
#define INLINE_VARIABLES 1
#else
#define INLINE_VARIABLES 0
#endif

#define SHADOWSYSCALL_COMPILETIME_HASH(str) []() { constexpr unsigned int hash = shadow_syscall::hash::chash(str); return hash; }()
#define SHADOWSYSCALL_RUNTIME_HASH(str) shadow_syscall::hash::hash(str)

#define shadowsyscall(type, syscall_name) [&]() { constexpr unsigned int hash = shadow_syscall::hash::chash(#syscall_name); \
			return ::shadow_syscall::internals::syscall_internals<type, hash>(); }()

namespace shadow_syscall {
	namespace PE
	{
		struct UNICODE_STRING {
			unsigned short length;
			unsigned short maximum_length;
			wchar_t* buffer;
		};

		typedef struct _LIST_ENTRY {
			struct _LIST_ENTRY* flink;
			struct _LIST_ENTRY* blink;
		} LIST_ENTRY, * PLIST_ENTRY, * PRLIST_ENTRY;

		typedef struct _LDR_DATA_TABLE_ENTRY {
			LIST_ENTRY in_load_order_links;
			LIST_ENTRY in_memory_order_links;
			void* reserved2[2];
			void* dll_base;
			void* entry_point;
			void* reserved3;
			UNICODE_STRING full_dll_name;
			UNICODE_STRING base_dll_name;
			void* reserved5[3];
			union {
				unsigned long check_sum;
				void* reserved6;
			};
			unsigned long time_date_stamp;
		} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

		typedef struct _PEB_LDR_DATA {
			unsigned long length;
			unsigned char initialized;
			void* ss_handle;
			LIST_ENTRY in_load_order_module_list;
			LIST_ENTRY in_memory_order_module_list;
			LIST_ENTRY in_initialization_order_module_list;
		} PEB_LDR_DATA, * PPEB_LDR_DATA;

		struct PEB {
			unsigned char   reserved1[2];
			unsigned char   being_debugged;
			unsigned char   reserved2[1];
			const char* reserved3[2];
			PEB_LDR_DATA* loader_data;
		};

		typedef struct _IMAGE_EXPORT_DIRECTORY {
			unsigned long  characteristics;
			unsigned long  time_date_stamp;
			unsigned short major_version;
			unsigned short minor_version;
			unsigned long  name;
			unsigned long  base;
			unsigned long  number_of_functions;
			unsigned long  number_of_names;
			unsigned long  address_of_functions; // RVA from base of image
			unsigned long  address_of_names; // RVA from base of image
			unsigned long  address_of_name_ordinals; // RVA from base of image
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
			unsigned short machine;
			unsigned short number_of_sections;
			unsigned long  time_date_stamp;
			unsigned long  pointer_to_symbol_table;
			unsigned long  number_of_symbols;
			unsigned short size_of_optional_header;
			unsigned short characteristics;
		};

		struct IMAGE_DATA_DIRECTORY {
			unsigned long virtual_address;
			unsigned long size;
		};

		typedef struct _IMAGE_OPTIONAL_HEADER64 {
			unsigned short magic;
			unsigned char major_linker_version;
			unsigned char minor_linker_version;
			unsigned long size_of_code;
			unsigned long size_of_initialized_data;
			unsigned long size_of_uninitialized_data;
			unsigned long address_of_entry_point;
			unsigned long base_of_code;
			unsigned long long image_base;
			unsigned long section_alignment;
			unsigned long file_alignment;
			unsigned short major_operating_system_version;
			unsigned short minor_operation_system_version;
			unsigned short major_image_version;
			unsigned short minor_image_version;
			unsigned short major_subsystem_version;
			unsigned short minor_subsystem_version;
			unsigned long win32_version_value;
			unsigned long size_of_image;
			unsigned long size_of_headers;
			unsigned long check_sum;
			unsigned short subsystem;
			unsigned short dll_characteristics;
			unsigned long long size_of_stack_reserve;
			unsigned long long size_of_stack_commit;
			unsigned long long size_of_heap_reserve;
			unsigned long long size_of_heap_commit;
			unsigned long loader_flags;
			unsigned long number_of_rva_and_sizes;
			IMAGE_DATA_DIRECTORY data_directory[16];
		} IMAGE_OPTIONAL_HEADER64, * PIMAGE_OPTIONAL_HEADER64;

		typedef struct _IMAGE_OPTIONAL_HEADER32 {
			unsigned short       magic;
			unsigned char        major_linker_version;
			unsigned char        minor_linker_version;
			unsigned long        size_of_code;
			unsigned long        size_of_initialized_data;
			unsigned long        size_of_uninitialized_data;
			unsigned long        address_of_entry_point;
			unsigned long        base_of_code;
			unsigned long        base_of_data;
			unsigned long        image_base;
			unsigned long        section_alignment;
			unsigned long        file_alignment;
			unsigned short       major_operating_system_version;
			unsigned short       minor_operation_system_version;
			unsigned short       major_image_version;
			unsigned short       minor_image_version;
			unsigned short       major_subsystem_version;
			unsigned short       minor_subsystem_version;
			unsigned long        win32_version_value;
			unsigned long        size_of_image;
			unsigned long        size_of_headers;
			unsigned long        check_sum;
			unsigned short       subsystem;
			unsigned short       dll_characteristics;
			unsigned long        size_of_stack_reserve;
			unsigned long        size_of_stack_commit;
			unsigned long        size_of_heap_reserve;
			unsigned long        size_of_heap_commit;
			unsigned long        loader_flags;
			unsigned long        number_of_rva_and_sizes;
			IMAGE_DATA_DIRECTORY data_directory[16];
		} IMAGE_OPTIONAL_HEADER32, * PIMAGE_OPTIONAL_HEADER32;

		typedef struct _IMAGE_NT_HEADERS {
#if defined(_M_X64)
			using IMAGE_OPT_HEADER_ARCH = IMAGE_OPTIONAL_HEADER64;
#elif defined(_M_IX86)
			using IMAGE_OPT_HEADER_ARCH = IMAGE_OPTIONAL_HEADER32;
#endif
			unsigned long signature;
			IMAGE_FILE_HEADER file_header;
			IMAGE_OPT_HEADER_ARCH optional_header;
		} IMAGE_NT_HEADERS, * PIMAGE_NT_HEADERS;
	}

	using pointer_t = unsigned long long;

#ifndef SHADOWSYSCALL_DISABLE_INTRIN_HASH

	namespace math
	{
		SHADOWSYSCALL_FORCEINLINE int _xor_(int p, int q) noexcept
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

		SHADOWSYSCALL_FORCEINLINE int _add_(int p, int q) noexcept
		{
#ifndef SHADOWSYSCALL_USE_AVX_INTRINS
			return _mm_cvtsi128_si32(_mm_add_epi32(_mm_set1_epi32(p), _mm_set1_epi32(q)));
#else
			return _mm_cvtsi128_si32(_mm256_castsi256_si128(_mm256_add_epi32(_mm256_set1_epi32(p), _mm256_set1_epi32(q))));
#endif
		}
	}

#endif

#ifndef SHADOWSYSCALL_DISABLE_EXCEPTIONS
	namespace exception
	{
		class simplest_exception
		{
		public:
			simplest_exception(const char* message) : m_message(message) {}

			const char* what() const noexcept
			{
				return m_message;
			}
		private:
			const char* m_message;
		};
	}
#endif

	namespace hash
	{
		constexpr unsigned int magic_value = (__TIME__[1] + __TIME__[4] + __TIME__[6] + __TIME__[7]) * 0x1923812857;

		template<class CharT = char, bool Runtime = false>
		SHADOWSYSCALL_FORCEINLINE constexpr unsigned int hash_single_char(unsigned int offset, unsigned int index, CharT c)
		{
#ifndef SHADOWSYSCALL_DISABLE_INTRIN_HASH
			if constexpr (Runtime) {
				return static_cast<unsigned int>(c + (math::_add_(math::_xor_(offset, c), (magic_value + index) * c)) *
					(math::_xor_(magic_value, (index == 0 ? magic_value : index))));
			}
#endif
			return static_cast<unsigned int>(c + (static_cast<int>(offset ^ c) + (magic_value + index) * c) *
				(magic_value ^ (index == 0 ? magic_value : index)));
		}

		template<bool CaseSensitive = SHADOWSYSCALL_CASE_SENSITIVITY>
		SHADOWSYSCALL_FORCEINLINE SHADOWSYSCALL_CONSTEVAL unsigned int chash(const char* str) noexcept
		{
			unsigned int result = magic_value;

			for (unsigned int i = 0; ; i++)
			{
				char c = str[i];
				if (c == '\0') break;
				result = hash_single_char(result, i, CaseSensitive ? SHADOWSYSCALL_TOLOWER(c) : c);
			}

			return result;
		}

		template<class CharT = char, bool CaseSensitive = SHADOWSYSCALL_CASE_SENSITIVITY>
		SHADOWSYSCALL_FORCEINLINE const unsigned int hash(const CharT* str) noexcept
		{
			unsigned int result = magic_value;

			for (unsigned int i = 0; ; i++)
			{
				CharT c = str[i];
				if (c == '\0') break;
				result = hash_single_char<CharT, true>(result, i, static_cast<CharT>(CaseSensitive ? SHADOWSYSCALL_TOLOWER(c) : c));
			}

			return result;
		}
	}

	namespace utils
	{
		template<typename T1, typename T2 = T1>
		struct pair
		{
			T1 first;
			T2 second;
		};

		SHADOWSYSCALL_FORCEINLINE void* memcpy(void* _Destination, const void* _Source, unsigned long long n)
		{
			char* d = static_cast<char*>(_Destination);
			const char* s = const_cast<char*>(static_cast<const char*>(_Source));

			for (unsigned long long i = 0; i < n; ++i)
			{
				d[i] = s[i];
			}

			return _Destination;
		}

		SHADOWSYSCALL_FORCEINLINE const ::shadow_syscall::PE::PEB* get_ppeb() noexcept
		{
#if defined(_M_X64)
			return reinterpret_cast<const ::shadow_syscall::PE::PEB*>(__readgsqword(0x60));
#elif defined(_M_IX86)
			return reinterpret_cast<const ::shadow_syscall::PE::PEB*>(__readfsdword(0x30));
#endif
		}

		SHADOWSYSCALL_FORCEINLINE const ::shadow_syscall::PE::PIMAGE_NT_HEADERS nt_header(
			pointer_t module_base) noexcept
		{
			return reinterpret_cast<::shadow_syscall::PE::PIMAGE_NT_HEADERS>(module_base + reinterpret_cast<const ::shadow_syscall::PE::IMAGE_DOS_HEADER*>(module_base)->e_lfanew);
		}

		SHADOWSYSCALL_FORCEINLINE const ::shadow_syscall::PE::IMAGE_DOS_HEADER* dos_header(
			pointer_t module_base) noexcept
		{
			return reinterpret_cast<::shadow_syscall::PE::IMAGE_DOS_HEADER*>(module_base);
		}

		SHADOWSYSCALL_FORCEINLINE const ::shadow_syscall::PE::IMAGE_NT_HEADERS::IMAGE_OPT_HEADER_ARCH* optional_header(
			pointer_t module_base) noexcept
		{
			return &nt_header(module_base)->optional_header;
		}

		SHADOWSYSCALL_FORCEINLINE const bool dos_header_empty(
			pointer_t module_base) noexcept
		{
			return optional_header(module_base)->data_directory[0].size <= 0ul;
		}

		SHADOWSYSCALL_FORCEINLINE const ::shadow_syscall::PE::PIMAGE_EXPORT_DIRECTORY image_export_dir(
			pointer_t module_base) noexcept
		{
			return reinterpret_cast<::shadow_syscall::PE::PIMAGE_EXPORT_DIRECTORY>(module_base +
				optional_header(module_base)->data_directory[0].virtual_address);
		}

		SHADOWSYSCALL_FORCEINLINE const pointer_t dll_base(
			::shadow_syscall::PE::_LDR_DATA_TABLE_ENTRY* table_entry) noexcept
		{
			return reinterpret_cast<pointer_t>(table_entry->dll_base);
		}

		SHADOWSYSCALL_FORCEINLINE const ::shadow_syscall::PE::PEB_LDR_DATA* loader_data() noexcept
		{
			return reinterpret_cast<const ::shadow_syscall::PE::PEB_LDR_DATA*>(get_ppeb()->loader_data);
		}

		SHADOWSYSCALL_FORCEINLINE const ::shadow_syscall::PE::LDR_DATA_TABLE_ENTRY* ldr_data_entry() noexcept
		{
			return reinterpret_cast<const ::shadow_syscall::PE::LDR_DATA_TABLE_ENTRY*>(loader_data()->in_load_order_module_list.flink);
		}

#ifndef SHADOWSYSCALL_DISABLE_CACHING
		template <class _Type1, class _Type2>
		SHADOWSYSCALL_FORCEINLINE const bool value_exists_in_map(
			std::unordered_map<_Type1, _Type2> _map, _Type1 _key) noexcept
		{
			return (_map.find(_key) != _map.end());
		}
#endif
	}

	namespace detail
	{
		class module_export_info {
		public:
			using const_pointer_t = const pointer_t;

			module_export_info(const_pointer_t base) noexcept : m_base(base)
			{
				const auto export_dir_data = ::shadow_syscall::utils::nt_header(base)->optional_header.data_directory[0];
				m_export_dir = reinterpret_cast<const ::shadow_syscall::PE::PIMAGE_EXPORT_DIRECTORY>(base + export_dir_data.virtual_address);
			}

			SHADOWSYSCALL_FORCEINLINE unsigned long size() const noexcept
			{
				return m_export_dir->number_of_names;
			}

			SHADOWSYSCALL_FORCEINLINE const char* const name(
				unsigned int iterator) const noexcept
			{
				return reinterpret_cast<const char*>(m_base + reinterpret_cast<const unsigned long*>(m_base + m_export_dir->address_of_names)[iterator]);
			}

			SHADOWSYSCALL_FORCEINLINE const_pointer_t address(
				unsigned int iterator) const noexcept
			{
				const auto rva_table = reinterpret_cast<unsigned long*>(m_base + m_export_dir->address_of_functions);
				const auto ord_table = reinterpret_cast<unsigned short*>(m_base + m_export_dir->address_of_name_ordinals);
				return m_base + rva_table[ord_table[iterator]];
			}

			SHADOWSYSCALL_FORCEINLINE bool module_integrity_checks() noexcept(SHADOWSYSCALL_EXCEPTION_HANDLING)
			{
				if (::shadow_syscall::utils::dos_header(m_base)->e_magic != IMAGE_DOS_SIGNATURE)
				{
#ifndef SHADOWSYSCALL_DISABLE_EXCEPTIONS
					throw ::shadow_syscall::exception::simplest_exception("DOS header e_magic mismatch");
#else
					return false;
#endif
				}

				if (::shadow_syscall::utils::nt_header(m_base)->optional_header.magic == IMAGE_NT_OPTIONAL_HDR_MAGIC &&
					::shadow_syscall::utils::optional_header(m_base)->data_directory[0].size <= 0ul)
				{
					return false;
				}

				return true;
			}

		private:
			const_pointer_t m_base;
			const ::shadow_syscall::PE::IMAGE_EXPORT_DIRECTORY* m_export_dir;
		};

		class syscall_enumerator
		{
		public:
			using const_pointer_t = const pointer_t;

			const_pointer_t find_export(
				const_pointer_t export_hash) noexcept(SHADOWSYSCALL_EXCEPTION_HANDLING)
			{
				auto entry = &::shadow_syscall::utils::loader_data()->in_load_order_module_list;
				pointer_t export_address = 0;

				for (auto i = entry->flink; i != entry; i = i->flink)
				{
					auto module_data = CONTAINING_RECORD(i, ::shadow_syscall::PE::LDR_DATA_TABLE_ENTRY, in_load_order_links);

					if (module_data->base_dll_name.buffer == nullptr)
						continue;

					pointer_t module_base = ::shadow_syscall::utils::dll_base(module_data);

					if (module_base == 0)
						continue;

					module_export_info exp(module_base);

					if (!exp.module_integrity_checks())
						continue;

					for (unsigned int i = 0; i < exp.size(); ++i) {
						if (export_hash == SHADOWSYSCALL_RUNTIME_HASH(exp.name(i))) {
							export_address = static_cast<const_pointer_t>(exp.address(i));
							break;
						}
					}

					if (export_address == 0) {
						continue;
					}

					return export_address;
				}

#ifndef SHADOWSYSCALL_DISABLE_EXCEPTIONS
				// Make sure that syscall name is right and module is loaded.
				throw ::shadow_syscall::exception::simplest_exception("Cannot find desired export.");
#endif

				return 0;
			}

			SHADOWSYSCALL_FORCEINLINE unsigned int syscall_id(
				const_pointer_t address) noexcept
			{
				return *reinterpret_cast<unsigned int*>(static_cast<const_pointer_t>(address + 4));
			}
		};
	}

	namespace internals
	{
		SHADOWSYSCALL_FORCEINLINE void* NtVirtualAlloc(pointer_t NtAllocateVirtualMemoryAddr,
			void* lpAddress, unsigned long long dwSize, unsigned long flAllocationType, unsigned long flProtect)
		{
			void* base_address = lpAddress;
			unsigned long long region_size = dwSize;

			long result = reinterpret_cast<long(__stdcall*)(void*, void*, unsigned long long, 
				unsigned long long*, unsigned long, unsigned long)>
				(NtAllocateVirtualMemoryAddr)(
					(void*)-1,
					&base_address,
					0,
					&region_size,
					flAllocationType & 0xFFFFFFC0,
					flProtect);

			if (NT_SUCCESS(result))
				return base_address;

			return nullptr;
		}

		SHADOWSYSCALL_FORCEINLINE int NtVirtualFree(pointer_t NtFreeVirtualMemoryAddr, 
			void* lpAddress, unsigned long long dwSize, unsigned long dwFreeType)
		{
			long result = 0;
			unsigned long long region_size = dwSize;
			void* base_address = lpAddress;

			if ((dwFreeType & 0xFFFF3FFC) != 0 || (dwFreeType & 0x8003) == 0x8000 && dwSize)
			{
				result = -0x3FFFFFF3;
			}

			result = reinterpret_cast<long(__stdcall*)(void*, void*, unsigned long long*, unsigned long)>(NtFreeVirtualMemoryAddr)(
				(void*)-1, &base_address, &region_size, dwFreeType);

			if (result == -0x3FFFFFBB)
			{
				result = reinterpret_cast<long(__stdcall*)(void*, void*, unsigned long long*, unsigned long)>(NtFreeVirtualMemoryAddr)(
					(void*)-1, &base_address, &region_size, dwFreeType);
			}

			return NT_SUCCESS(result);
		}

		template<unsigned int shellcode_size>
		class shellcode_allocator
		{
		public:
			using byte_t = unsigned char;
			using value_t = unsigned int;

			template<class... ArgPack>
			shellcode_allocator(ArgPack... list) noexcept : m_shellcode_data{ static_cast<byte_t>(list)... } {}

			void allocate_memory(pointer_t virtualAllocAddr) noexcept
			{
				m_memory = NtVirtualAlloc(virtualAllocAddr, nullptr, shellcode_size, 0x00001000 | 0x00002000, 0x40);

				if (m_memory == nullptr)
				{
#ifndef SHADOWSYSCALL_DISABLE_EXCEPTIONS
					throw ::shadow_syscall::exception::simplest_exception("Can't allocate virtual memory");
#else
					return;
#endif
				}

				utils::memcpy(m_memory, m_shellcode_data, shellcode_size);
				m_shellcode_fn = m_memory;
			}

			void deallocate_memory(pointer_t virtualFreeAddr) noexcept
			{
				if (m_memory != nullptr)
				{
					NtVirtualFree(virtualFreeAddr, m_memory, 0, 0x00008000);
					m_memory = nullptr;
				}
			}

			void set_byte(value_t index, value_t value) noexcept
			{
				*reinterpret_cast<value_t*>(&m_shellcode_data[index]) = value;
			}

			const void* operator()() const noexcept
			{
				return m_shellcode_fn;
			}

		private:
			void* m_memory = nullptr;
			void* m_shellcode_fn = nullptr;
			byte_t m_shellcode_data[shellcode_size];
		};

		// For "/std:c++14"
#if !(INLINE_VARIABLES)
#ifndef SHADOWSYSCALL_DISABLE_CACHING
		static std::unordered_map<unsigned int, unsigned int> syscall_index_map;
#endif
		static ::shadow_syscall::utils::pair<pointer_t> virtual_routine_address;
#endif

		template <class ReturnType, unsigned int export_hash>
		class syscall_internals
		{
		public:
			using value_t = unsigned int;

			SHADOWSYSCALL_FORCEINLINE syscall_internals() noexcept
			{
				if (virtual_routine_address.first != 0 || virtual_routine_address.second != 0)
					return;

				detail::syscall_enumerator e;
				virtual_routine_address.first = e.find_export(SHADOWSYSCALL_COMPILETIME_HASH("NtAllocateVirtualMemory"));
				virtual_routine_address.second = e.find_export(SHADOWSYSCALL_COMPILETIME_HASH("NtFreeVirtualMemory"));
			}

			SHADOWSYSCALL_FORCEINLINE ~syscall_internals()
			{
				m_syscallShell.deallocate_memory(virtual_routine_address.second);
			}

			template<class... Args>
			SHADOWSYSCALL_FORCEINLINE ReturnType call(Args... args) noexcept
			{
				find_syscall_id();
				setup_shellcode();

				return reinterpret_cast<ReturnType(__stdcall*)(Args...)>(m_syscallShell())(args...);
			}

			template<class... Args>
			SHADOWSYSCALL_FORCEINLINE ReturnType cached_call(Args... args) noexcept
			{
#ifndef SHADOWSYSCALL_DISABLE_CACHING
				if (::shadow_syscall::utils::value_exists_in_map<value_t, value_t>(
					syscall_index_map, export_hash))
				{
					m_syscallId = syscall_index_map.at(export_hash);
					setup_shellcode();
				}
				else
				{
					find_syscall_id();
					syscall_index_map.insert(std::make_pair(export_hash, m_syscallId));
					setup_shellcode();
				}
#else
				find_syscall_id();
				setup_shellcode();
#endif

				return reinterpret_cast<ReturnType(__stdcall*)(Args...)>(m_syscallShell())(args...);
			}

		private:
			SHADOWSYSCALL_FORCEINLINE void find_syscall_id() noexcept
			{
				::shadow_syscall::detail::syscall_enumerator e;
				const pointer_t export_address = e.find_export(export_hash);
				m_syscallId = e.syscall_id(export_address);
			}

			SHADOWSYSCALL_FORCEINLINE void setup_shellcode() noexcept
			{
				m_syscallShell.set_byte(6, m_syscallId);
				m_syscallShell.allocate_memory(virtual_routine_address.first);
			}

			value_t m_syscallId = 0;
			shellcode_allocator<13> m_syscallShell =
			{
				0x49, 0x89, 0xCA,                           // mov r10, rcx
				0x48, 0xC7, 0xC0, 0x3F, 0x10, 0x00, 0x00,   // mov rax, syscall_index
				0x0F, 0x05,                                 // syscall
				0xC3                                        // ret
			};

#if INLINE_VARIABLES
#ifndef SHADOWSYSCALL_DISABLE_CACHING
			static inline std::unordered_map<value_t, value_t> syscall_index_map;
#endif
			static inline ::shadow_syscall::utils::pair<pointer_t> virtual_routine_address;
#endif
		};
	}
}

#endif // SHADOW_SYSCALLS_SHELL_HPP
