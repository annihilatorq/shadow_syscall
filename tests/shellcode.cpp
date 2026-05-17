#include "omni/detail/shellcode.hpp"
#include "test_utils.hpp"

ut::suite<"omni::detail::shellcode"> shellcode_suite = [] {
  "move construction transfers executable buffer ownership"_test = [] {
    omni::detail::shellcode<1> source{{0xC3}};
    source.setup();

    void* executable_buffer = source.ptr<void>();

    expect(fatal(executable_buffer != nullptr));

    omni::detail::shellcode<1> moved{std::move(source)};

    expect(source.ptr<void>() == nullptr);
    expect(moved.ptr<void>() == executable_buffer);

    moved.execute();
  };

  "move assignment transfers executable buffer ownership"_test = [] {
    omni::detail::shellcode<1> source{{0xC3}};
    source.setup();

    omni::detail::shellcode<1> target{{0xC3}};
    target.setup();

    void* executable_buffer = source.ptr<void>();

    expect(fatal(executable_buffer != nullptr));
    expect(fatal(target.ptr<void>() != nullptr));

    target = std::move(source);

    expect(source.ptr<void>() == nullptr);
    expect(target.ptr<void>() == executable_buffer);

    target.execute();
  };
};
