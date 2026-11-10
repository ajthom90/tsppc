#include "harness.h"

void test_bytes(void);
void test_blake2s(void);
void test_aead(void);

int main(void)
{
    test_bytes();
    test_blake2s();
    test_aead();
    return t_summary();
}
