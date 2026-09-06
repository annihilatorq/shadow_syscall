#include "omni/error.hpp"
#include "test_utils.hpp"

ut::suite<"omni::error"> error_suite = [] {
  "NTSTATUS values use the NT error category"_test = [] {
    const auto error = omni::make_error_code(omni::ntstatus::access_denied);

    expect(&error.category() == &omni::nt_error_category());
#ifdef OMNI_HAS_ERROR_STRINGS
    expect(not error.message().empty());
#endif
  };
};
