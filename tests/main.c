#include "harness.h"

void test_bytes(void);
void test_blake2s(void);

int main(void)
{
    test_bytes();
    test_blake2s();
    return t_summary();
}
