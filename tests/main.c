#include "harness.h"

void test_bytes(void);
void test_blake2s(void);
void test_aead(void);
void test_nacl(void);

int main(void)
{
    test_bytes();
    test_blake2s();
    test_aead();
    test_nacl();
    return t_summary();
}
