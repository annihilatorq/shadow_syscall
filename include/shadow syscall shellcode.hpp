// [FAQ] here: https://github.com/annihilatorq/shadow_syscall

// Creator Discord - @ntraiseharderror, Telegram - https://t.me/ntraiseharderror, Github - https://github.com/annihilatorq.
// Special thanks to @inversion

#ifndef SHADOW_SYSCALLS_SHELL_HPP
#define SHADOW_SYSCALLS_SHELL_HPP

#ifndef _M_X64
#error Currently unsupported target architecture.
#endif

#if !(__clang__)
#include <intrin.h>
#else
#define SHADOWSYSCALL_DISABLE_INTRIN_HASH
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
#define INLINE_VARIABLES true
#else
#define INLINE_VARIABLES false
#endif

#define SHADOWSYSCALL_CHASH(str) []() { constexpr unsigned int hash = shadow_syscall::hash::chash(str); return hash; }()
#define SHADOWSYSCALL_RHASH(str) shadow_syscall::hash::hash(str)

#define shadowsyscall(type, syscall_name) [&]() { constexpr unsigned int hash = shadow_syscall::hash::chash(#syscall_name); \
			return shadow_syscall::syscall<type, hash>(); }()

namespace shadow_syscall {
	using pointer_t = unsigned long long;

	namespace PE
	{
		struct unicode_string {
			unsigned short length;
			unsigned short maximum_length;
			wchar_t* buffer;
		};

		struct list_entry {
			list_entry* flink;
			list_entry* blink;
		};

		struct ldr_data_table_entry {
			list_entry in_load_order_links;
			list_entry in_memory_order_links;
			void* reserved2[2];
			void* dll_base;
			void* entry_point;
			void* reserved3;
			unicode_string full_dll_name;
			unicode_string base_dll_name;
			void* reserved5[3];
			union {
				unsigned long check_sum;
				void* reserved6;
			};
			unsigned long time_date_stamp;
		};

		struct peb_ldr_data_t {
			unsigned long length;
			unsigned char initialized;
			void* ss_handle;
			list_entry in_load_order_module_list;
			list_entry in_memory_order_module_list;
			list_entry in_initialization_order_module_list;
		};

		struct peb_t {
			unsigned char reserved1[2];
			unsigned char being_debugged;
			unsigned char reserved2[1];
			const char* reserved3[2];
			peb_ldr_data_t* ldr_data;

			static const auto address() noexcept 
			{ 
#if defined(__clang__)
				const peb_t* ptr;
				__asm__ __volatile__("mov %%gs:0x60, %0" : "=r"(ptr));
				return ptr;
#elif defined(_MSC_VER)
				return reinterpret_cast<const peb_t*>(__readgsqword(0x60));
#endif
			}

			static const auto loader_data() noexcept { return reinterpret_cast<const peb_ldr_data_t*>(address()->ldr_data); }
		};

		struct image_export_directory {
			unsigned long  characteristics;
			unsigned long  time_date_stamp;
			unsigned short major_version;
			unsigned short minor_version;
			unsigned long  name;
			unsigned long  base;
			unsigned long  number_of_functions;
			unsigned long  number_of_names;
			unsigned long  address_of_functions;
			unsigned long  address_of_names;
			unsigned long  address_of_name_ordinals;

			decltype(auto) rva_table(unsigned long long base) { return (unsigned long*)(base + address_of_functions); }
			decltype(auto) ordinal_table(unsigned long long base) { return (unsigned short*)(base + address_of_name_ordinals); }
		};

		struct dos_header_t
		{
			unsigned short e_magic;
			unsigned short e_cblp;
			unsigned short e_cp;
			unsigned short e_crlc;
			unsigned short e_cparhdr;
			unsigned short e_minalloc;
			unsigned short e_maxalloc;
			unsigned short e_ss;
			unsigned short e_sp;
			unsigned short e_csum;
			unsigned short e_ip;
			unsigned short e_cs;
			unsigned short e_lfarlc;
			unsigned short e_ovno;
			unsigned short e_res[4];
			unsigned short e_oemid;
			unsigned short e_oeminfo;
			unsigned short e_res2[10];
			long e_lfanew;

			static const auto base(pointer_t module_handle) noexcept { return reinterpret_cast<dos_header_t*>(module_handle); }
		};

		struct file_header_t {
			unsigned short machine;
			unsigned short number_of_sections;
			unsigned long  time_date_stamp;
			unsigned long  pointer_to_symbol_table;
			unsigned long  number_of_symbols;
			unsigned short size_of_optional_header;
			unsigned short characteristics;
		};

		struct data_directory_t {
			unsigned long virtual_address;
			unsigned long size;

			const bool empty() noexcept { return size <= 0; }
		};

		struct nt_headers_t;

		struct optional_header_x64_t {
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
			data_directory_t data_directory[16];
		};

		struct nt_headers_t
		{
			unsigned long signature;
			file_header_t file_header;
			optional_header_x64_t optional_header;

			static const auto base(pointer_t module_handle) noexcept { return reinterpret_cast<nt_headers_t*>(module_handle + reinterpret_cast<const dos_header_t*>(module_handle)->e_lfanew); }
			static const auto opt_header(pointer_t module_handle) noexcept { return &base(module_handle)->optional_header; }
		};
	}

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

	namespace map_impl
	{
		template<typename T1, typename T2 = T1>
		struct pair
		{
			T1 first;
			T2 second;
		};

#ifndef SHADOWSYSCALL_DISABLE_CACHING

		// This map implementation does not pretend to be released
		// in std::cpp-26, it is the simplest, in terms of security
		// not comparable to stl implementation, which performs its
		// functionality properly. We don't need more in this implementation.
		//
		template <typename key_t, typename value_t>
		class map
		{
		public:
			map() : root(nullptr) {}

			bool contains(const key_t& key) const
			{
				return find(root, key) != nullptr;
			}

			void insert(const pair<key_t, value_t>& key_value)
			{
				root = insert(root, key_value.first, key_value.second);
			}

			value_t find(const key_t& key) const
			{
				node_t* result = find(root, key);
				return result != nullptr ? result->value : value_t{};
			}

			value_t& at(const key_t& key)
			{
				node_t* result = find(root, key);

#ifndef SHADOWSYSCALL_DISABLE_EXCEPTIONS
				if (result == nullptr) {
					throw exception::simplest_exception("key not found in map");
				}

				return result->value;
#else
				return result != nullptr ? result->value : value_t{};
#endif
			}

			const value_t& at(const key_t& key) const
			{
				node_t* result = find(root, key);

#ifndef SHADOWSYSCALL_DISABLE_EXCEPTIONS
				if (result == nullptr) {
					throw exception::simplest_exception("key not found in map");
				}

				return result->value;
#else
				return result != nullptr ? result->value : value_t{};
#endif
			}

			value_t& operator[](const key_t& key)
			{
				node_t* result = find(root, key);
				if (result == nullptr) {
					root = insert(root, key, value_t{});
					result = find(root, key);
				}
				return result->value;
			}

		private:
			struct node_t
			{
				key_t key;
				value_t value;
				node_t* left;
				node_t* right;

				node_t(const key_t& k, const value_t& v) : key(k), value(v), left(nullptr), right(nullptr) {}
			};

			node_t* root;

			node_t* insert(node_t* node, const key_t& key, const value_t& value)
			{
				if (node == nullptr) {
					return new node_t(key, value);
				}

				if (key < node->key) {
					node->left = insert(node->left, key, value);
				}
				else if (key > node->key) {
					node->right = insert(node->right, key, value);
				}
				else {
					node->value = value;
				}

				return node;
			}

			node_t* find(node_t* node, const key_t& key) const
			{
				if (node == nullptr) {
					return nullptr;
				}

				if (key < node->key) {
					return find(node->left, key);
				}
				else if (key > node->key) {
					return find(node->right, key);
				}
				else {
					return node;
				}
			}
		};

#endif
	}

	namespace hash
	{
		constexpr unsigned int hash_seed()
		{
			unsigned int value = 0x31892571;
			for (char c : __TIME__)
				value = static_cast<unsigned int>((value ^ c) * 0x38127512u);
			return value;
		}

		constexpr unsigned int magic_value = hash_seed();

		template<class char_t = char, bool runtime = false>
		SHADOWSYSCALL_FORCEINLINE constexpr unsigned int hash_single(unsigned int offset, unsigned int index, char_t c)
		{
#ifndef SHADOWSYSCALL_DISABLE_INTRIN_HASH
			if constexpr (runtime) {
				return static_cast<unsigned int>(c + (math::_add_(math::_xor_(offset, c), (magic_value + index) * c)) *
					(math::_xor_(magic_value, (index == 0 ? magic_value : index))));
			}
#endif
			return static_cast<unsigned int>(c + (static_cast<unsigned int>(offset ^ c) + (magic_value + index) * c) *
				(magic_value ^ (index == 0 ? magic_value : index)));
		}

		template<bool case_sensitive = SHADOWSYSCALL_CASE_SENSITIVITY>
		SHADOWSYSCALL_FORCEINLINE constexpr unsigned int chash(const char* str, unsigned int result = magic_value, unsigned int i = 0) noexcept
		{
			char c = str[i];

			if (c == '\0') {
				return result;
			}

			return chash(str, hash_single(result, i, case_sensitive ? SHADOWSYSCALL_TOLOWER(c) : c), i + 1);
		}

		template<class char_t = char, bool case_sensitive = SHADOWSYSCALL_CASE_SENSITIVITY>
		SHADOWSYSCALL_FORCEINLINE const unsigned int hash(const char_t* str) noexcept
		{
			unsigned int result = magic_value;

			for (unsigned int i = 0; ; i++)
			{
				char_t c = str[i];
				if (c == '\0') break;
				result = hash_single<char_t, true>(result, i, static_cast<char_t>(case_sensitive ? SHADOWSYSCALL_TOLOWER(c) : c));
			}

			return result;
		}
	}

	namespace utils
	{
		SHADOWSYSCALL_FORCEINLINE void* memcpy(void* _Destination, const void* _Source, unsigned long long n)
		{
			auto d = static_cast<char*>(_Destination);
			const char* s = const_cast<char*>(static_cast<const char*>(_Source));

			for (unsigned long long i = 0; i < n; ++i)
				d[i] = s[i];

			return _Destination;
		}
	}

	class module_export_info {
	public:
		using const_pointer_t = const pointer_t;

		module_export_info(const_pointer_t base) noexcept : m_module_base(base)
		{
			const auto export_dir_data = ::shadow_syscall::PE::nt_headers_t::base(base)->optional_header.data_directory[0];
			m_export_dir = reinterpret_cast<::shadow_syscall::PE::image_export_directory*>(base + export_dir_data.virtual_address);
		}

		auto size() const noexcept
		{
			return m_export_dir->number_of_names;
		}

		auto name(unsigned int iterator) const noexcept
		{
			return reinterpret_cast<const char*>(m_module_base + reinterpret_cast<const unsigned long*>(m_module_base + m_export_dir->address_of_names)[iterator]);
		}

		const_pointer_t address(unsigned int iterator) const noexcept
		{
			const auto rva_table = m_export_dir->rva_table(m_module_base);
			const auto ord_table = m_export_dir->ordinal_table(m_module_base);
			return m_module_base + rva_table[ord_table[iterator]];
		}

		bool module_integrity_checks() noexcept(SHADOWSYSCALL_EXCEPTION_HANDLING)
		{
			if (::shadow_syscall::PE::dos_header_t::base(m_module_base)->e_magic != IMAGE_DOS_SIGNATURE)
			{
#ifndef SHADOWSYSCALL_DISABLE_EXCEPTIONS
				throw ::shadow_syscall::exception::simplest_exception("DOS header e_magic mismatch");
#else
				return false;
#endif
			}

			if (::shadow_syscall::PE::nt_headers_t::base(m_module_base)->optional_header.magic == IMAGE_NT_OPTIONAL_HDR_MAGIC &&
				::shadow_syscall::PE::nt_headers_t::opt_header(m_module_base)->data_directory[0].empty())
			{
				return false;
			}

			return true;
		}

	private:
		const_pointer_t m_module_base;
		::shadow_syscall::PE::image_export_directory* m_export_dir;
	};

	class export_enumerator {
	public:
		using const_pointer_t = const pointer_t;

		const_pointer_t find_export(const_pointer_t export_hash) noexcept(SHADOWSYSCALL_EXCEPTION_HANDLING)
		{
			auto entry = &::shadow_syscall::PE::peb_t::loader_data()->in_load_order_module_list;
			pointer_t export_address = 0;

			for (auto i = entry->flink; i != entry; i = i->flink)
			{
				auto it_module = CONTAINING_RECORD(i, ::shadow_syscall::PE::ldr_data_table_entry, in_load_order_links);

				if (it_module->base_dll_name.buffer == nullptr)
					continue;

				pointer_t module_base = reinterpret_cast<pointer_t>(it_module->dll_base);

				if (module_base == 0)
					continue;

				module_export_info exp(module_base);

				if (!exp.module_integrity_checks())
					continue;

				for (unsigned int i = 0; i < exp.size(); ++i) {
					if (export_hash == SHADOWSYSCALL_RHASH(exp.name(i))) {
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
			//
			throw ::shadow_syscall::exception::simplest_exception("Cannot find desired export.");
#endif

			return 0;
		}

		SHADOWSYSCALL_FORCEINLINE auto syscall_id(const_pointer_t address) noexcept
		{
			// The syscall index is always stored at: address + 4 bytes
			//
			return *reinterpret_cast<unsigned int*>(static_cast<const_pointer_t>(address + 4));
		}
	};

	namespace kernelbase
	{
		using ntstatus = long;

		SHADOWSYSCALL_FORCEINLINE void* nt_virtual_alloc(pointer_t nt_allocate_virtual_memory, void* lpAddress, unsigned long long dwSize, unsigned long flAllocationType, unsigned long flProtect)
		{
			using call_type = ntstatus(__stdcall*)(void*, void*, unsigned long long, unsigned long long*, unsigned long, unsigned long);

			void* base_address = lpAddress;
			unsigned long long region_size = dwSize;

			ntstatus result = reinterpret_cast<call_type>(nt_allocate_virtual_memory)((void*)-1, &base_address, 0, &region_size, flAllocationType & 0xFFFFFFC0, flProtect);

			if (NT_SUCCESS(result)) {
				return base_address;
			}

			return nullptr;
		}

		SHADOWSYSCALL_FORCEINLINE int nt_virtual_free(pointer_t nt_free_virtual_memory, void* lpAddress, unsigned long long dwSize, unsigned long dwFreeType)
		{
			using call_type = ntstatus(__stdcall*)(void*, void*, unsigned long long*, unsigned long);

			ntstatus result = 0;
			unsigned long long region_size = dwSize;
			void* base_address = lpAddress;

			if ((dwFreeType & 0xFFFF3FFC) != 0 || (dwFreeType & 0x8003) == 0x8000 && dwSize)
			{
				result = -0x3FFFFFF3;
			}

			result = reinterpret_cast<call_type>(nt_free_virtual_memory)((void*)-1, &base_address, &region_size, dwFreeType);

			if (result == -0x3FFFFFBB)
			{
				result = reinterpret_cast<call_type>(nt_free_virtual_memory)((void*)-1, &base_address, &region_size, dwFreeType);
			}

			return NT_SUCCESS(result);
		}
	}

	template<unsigned int shellcode_size>
	class shellcode_allocator
	{
	public:
		template<class... Args>
		shellcode_allocator(Args&&... list) noexcept : m_shellcode_data{ static_cast<unsigned char>(list)... } {}

		void allocate(const pointer_t& virtual_alloc_addr) noexcept
		{
			m_memory = kernelbase::nt_virtual_alloc(virtual_alloc_addr, nullptr, shellcode_size, 0x00001000 | 0x00002000, 0x40);

			if (m_memory == nullptr)
			{
#ifndef SHADOWSYSCALL_DISABLE_EXCEPTIONS
				throw exception::simplest_exception("Can't allocate virtual memory");
#else
				return;
#endif
			}

			utils::memcpy(m_memory, m_shellcode_data, shellcode_size);
			m_shellcode_fn = m_memory;
		}

		void deallocate(const pointer_t& virtual_free_addr) noexcept
		{
			if (m_memory == nullptr)
				return;

			kernelbase::nt_virtual_free(virtual_free_addr, m_memory, 0, 0x00008000);
			m_memory = nullptr;
		}

		void set_byte(const unsigned int& index, const unsigned int& value) noexcept
		{
			*reinterpret_cast<unsigned int*>(&m_shellcode_data[index]) = value;
		}

		void* operator()() noexcept
		{
			return m_shellcode_fn;
		}

	private:
		void* m_memory = nullptr;
		void* m_shellcode_fn = nullptr;
		unsigned char m_shellcode_data[shellcode_size];
	};

	// For "/std:c++14"
	//
#if !(INLINE_VARIABLES)
#ifndef SHADOWSYSCALL_DISABLE_CACHING
	static ::shadow_syscall::map_impl::map<unsigned int, unsigned int> syscall_index_map;
#endif
	static ::shadow_syscall::map_impl::pair<pointer_t> virtual_routine_address;
#endif

	template <class function_t, unsigned int export_hash>
	class syscall
	{
	public:
		SHADOWSYSCALL_FORCEINLINE syscall() noexcept
		{
			if (virtual_routine_address.first != 0 || virtual_routine_address.second != 0)
				return;

			export_enumerator e;
			virtual_routine_address.first = e.find_export(SHADOWSYSCALL_CHASH("NtAllocateVirtualMemory"));
			virtual_routine_address.second = e.find_export(SHADOWSYSCALL_CHASH("NtFreeVirtualMemory"));
		}

		SHADOWSYSCALL_FORCEINLINE ~syscall() noexcept
		{
			m_syscall_shell.deallocate(virtual_routine_address.second);
		}

		template<class... Args>
		SHADOWSYSCALL_FORCEINLINE function_t call(Args... args) noexcept
		{
			find_syscall_id();
			setup_shellcode();

			return reinterpret_cast<function_t(*)(Args...)>(m_syscall_shell())(args...);
		}

		template<class... Args>
		SHADOWSYSCALL_FORCEINLINE function_t cached_call(Args... args) noexcept
		{
#ifndef SHADOWSYSCALL_DISABLE_CACHING
			if (syscall_index_map.contains(export_hash))
			{
				m_syscall_id = syscall_index_map.at(export_hash);
				setup_shellcode();
			}
			else
			{
				find_syscall_id();
				syscall_index_map.insert({ export_hash, m_syscall_id });
				setup_shellcode();
			}
#else
			find_syscall_id();
			setup_shellcode();
#endif

			return reinterpret_cast<function_t(*)(Args...)>(m_syscall_shell())(args...);
		}

	private:
		SHADOWSYSCALL_FORCEINLINE void find_syscall_id() noexcept
		{
			export_enumerator e;
			const pointer_t export_address = e.find_export(export_hash);
			m_syscall_id = e.syscall_id(export_address);
		}

		SHADOWSYSCALL_FORCEINLINE void setup_shellcode() noexcept
		{
			m_syscall_shell.set_byte(6, m_syscall_id);
			m_syscall_shell.allocate(virtual_routine_address.first);
		}	

		unsigned int m_syscall_id = 0;
		shellcode_allocator<13> m_syscall_shell =
		{
			0x49, 0x89, 0xCA,                           // mov r10, rcx
			0x48, 0xC7, 0xC0, 0x3F, 0x10, 0x00, 0x00,   // mov rax, syscall_index
			0x0F, 0x05,                                 // syscall
			0xC3                                        // ret
		};

#if INLINE_VARIABLES
#ifndef SHADOWSYSCALL_DISABLE_CACHING
		static inline ::shadow_syscall::map_impl::map<unsigned int, unsigned int> syscall_index_map;
#endif
		static inline ::shadow_syscall::map_impl::pair<pointer_t> virtual_routine_address;
#endif
	};
}

#endif // SHADOW_SYSCALLS_SHELL_HPP
