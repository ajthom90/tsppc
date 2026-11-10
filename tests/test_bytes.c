#include "harness.h"
#include "../src/core/bytes.h"

void test_bytes(void)
{
    uint8_t raw[16], *p = raw + 1;   /* deliberately odd address */
    ts_put_be32(p, 0x01020304); t_hex("be32", p, 4, "01020304");
    ts_put_le32(p, 0x01020304); t_hex("le32", p, 4, "04030201");
    ts_put_be64(p, 0x0102030405060708ULL); t_hex("be64", p, 8, "0102030405060708");
    ts_put_le64(p, 0x0102030405060708ULL); t_hex("le64", p, 8, "0807060504030201");
    t_true("get be16", ts_get_be16((const uint8_t*)"\x12\x34") == 0x1234);
    t_true("get le16", ts_get_le16((const uint8_t*)"\x12\x34") == 0x3412);
    ts_put_be64(p, 0xfedcba9876543210ULL);
    t_true("be64 round", ts_get_be64(p) == 0xfedcba9876543210ULL);
    ts_put_le64(p, 0xfedcba9876543210ULL);
    t_true("le64 round", ts_get_le64(p) == 0xfedcba9876543210ULL);
    ts_put_be32(p, 0xffffffff); ts_wipe(p, 4);
    t_hex("wipe", p, 4, "00000000");
}
