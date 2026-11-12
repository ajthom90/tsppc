#include "harness.h"

void test_bytes(void);
void test_blake2s(void);
void test_aead(void);
void test_nacl(void);
void test_encoding(void);
void test_json(void);
void test_hpack(void);
void test_h2(void);
void test_noise(void);
void test_net(void);
void test_store(void);
void test_netmap(void);
void test_session(void);
void test_ipc(void);
void test_ipc_reply(void);
void test_menu_model(void);
void test_filter(void);

int main(void)
{
    test_bytes();
    test_blake2s();
    test_aead();
    test_nacl();
    test_encoding();
    test_json();
    test_hpack();
    test_h2();
    test_noise();
    test_net();
    test_store();
    test_netmap();
    test_session();
    test_ipc();
    test_ipc_reply();
    test_menu_model();
    test_filter();
    return t_summary();
}
