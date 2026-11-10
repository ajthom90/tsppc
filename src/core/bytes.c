#include "bytes.h"

uint16_t ts_get_be16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

uint32_t ts_get_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16)
         | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

uint64_t ts_get_be64(const uint8_t *p)
{
    return ((uint64_t)ts_get_be32(p) << 32) | ts_get_be32(p + 4);
}

uint16_t ts_get_le16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[1] << 8) | p[0]);
}

uint32_t ts_get_le32(const uint8_t *p)
{
    return ((uint32_t)p[3] << 24) | ((uint32_t)p[2] << 16)
         | ((uint32_t)p[1] << 8) | (uint32_t)p[0];
}

uint64_t ts_get_le64(const uint8_t *p)
{
    return ((uint64_t)ts_get_le32(p + 4) << 32) | ts_get_le32(p);
}

void ts_put_be16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

void ts_put_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

void ts_put_be64(uint8_t *p, uint64_t v)
{
    ts_put_be32(p, (uint32_t)(v >> 32));
    ts_put_be32(p + 4, (uint32_t)v);
}

void ts_put_le16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
}

void ts_put_le32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

void ts_put_le64(uint8_t *p, uint64_t v)
{
    ts_put_le32(p, (uint32_t)v);
    ts_put_le32(p + 4, (uint32_t)(v >> 32));
}

void ts_wipe(void *p, size_t n)
{
    volatile uint8_t *q = (volatile uint8_t *)p;
    while (n--)
        *q++ = 0;
}
