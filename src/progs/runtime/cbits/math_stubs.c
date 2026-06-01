#include <stdint.h>

double frexp(double x, int *exp) {
    *exp = 0;
    return x;
}

double log(double x) {
    return x;
}

double ceil(double x) {
    int i = (int)x;
    if (x > i) return i + 1;
    return x;
}

double ldexp(double x, int exp) {
    return x;
}
