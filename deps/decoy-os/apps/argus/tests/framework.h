#ifndef __TEST_FRAMEWORK_H
#define __TEST_FRAMEWORK_H

#include <stdio.h>
#include <string.h>

static int _pass = 0;
static int _fail = 0;

#define ASSERT_EQ(a, b) do { \
    if ((a) == (b)) { _pass++; } \
    else { \
        fprintf(stderr, "FAIL [%s:%d] %s == %s  (%lld != %lld)\n", \
                __FILE__, __LINE__, #a, #b, (long long)(a), (long long)(b)); \
        _fail++; \
    } \
} while (0)

#define ASSERT_STR_EQ(a, b) do { \
    if (strcmp((a), (b)) == 0) { _pass++; } \
    else { \
        fprintf(stderr, "FAIL [%s:%d] \"%s\" != \"%s\"\n", \
                __FILE__, __LINE__, (a), (b)); \
        _fail++; \
    } \
} while (0)

#define ASSERT_TRUE(cond) do { \
    if (cond) { _pass++; } \
    else { \
        fprintf(stderr, "FAIL [%s:%d] %s is false\n", \
                __FILE__, __LINE__, #cond); \
        _fail++; \
    } \
} while (0)

#define ASSERT_NULL(p) do { \
    if ((p) == NULL) { _pass++; } \
    else { \
        fprintf(stderr, "FAIL [%s:%d] %s is not NULL\n", \
                __FILE__, __LINE__, #p); \
        _fail++; \
    } \
} while (0)

#define TEST_SUMMARY() do { \
    int total = _pass + _fail; \
    printf("%s  %d/%d passed\n", _fail == 0 ? "OK  " : "FAIL", _pass, total); \
    return _fail > 0 ? 1 : 0; \
} while (0)

#endif /* __TEST_FRAMEWORK_H */
