#pragma once
// ---------------------------------------------------------------------------
// test_helpers.h — Minimal assertion macros (no external test framework)
//
// We avoid pulling in GoogleTest / Catch2 to keep dependencies at zero.
// Each test executable uses these macros and returns 0 on success / 1 on
// failure.
// ---------------------------------------------------------------------------

#include <cstdlib>
#include <iostream>
#include <string_view>

inline int g_test_failures = 0;

#define ASSERT_EQ(a, b)                                                      \
    do {                                                                     \
        auto _a = (a);                                                       \
        auto _b = (b);                                                       \
        if (_a != _b) {                                                      \
            std::cerr << __FILE__ << ":" << __LINE__ << ": FAIL: "           \
                      << #a << " == " << #b << "  (" << _a << " != " << _b  \
                      << ")\n";                                              \
            ++g_test_failures;                                               \
        }                                                                    \
    } while (false)

#define ASSERT_TRUE(expr)                                                    \
    do {                                                                     \
        if (!(expr)) {                                                       \
            std::cerr << __FILE__ << ":" << __LINE__ << ": FAIL: "           \
                      << #expr << " is false\n";                             \
            ++g_test_failures;                                               \
        }                                                                    \
    } while (false)

#define ASSERT_THROWS(expr, exception_type)                                  \
    do {                                                                     \
        bool _caught = false;                                                \
        try { expr; } catch (const exception_type&) { _caught = true; }      \
        if (!_caught) {                                                      \
            std::cerr << __FILE__ << ":" << __LINE__ << ": FAIL: "           \
                      << #expr << " did not throw " #exception_type "\n";    \
            ++g_test_failures;                                               \
        }                                                                    \
    } while (false)

#define RUN_TESTS()                                                          \
    do {                                                                     \
        if (g_test_failures == 0) {                                          \
            std::cerr << "All tests passed.\n";                              \
            return 0;                                                        \
        } else {                                                             \
            std::cerr << g_test_failures << " test(s) FAILED.\n";            \
            return 1;                                                        \
        }                                                                    \
    } while (false)
