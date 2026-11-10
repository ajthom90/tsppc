#ifndef TS_CORE_BYTES_H
#define TS_CORE_BYTES_H

#include <stddef.h>
#include <stdint.h>

/* Explicit byte-order helpers. Safe on unaligned pointers and any host order. */
uint16_t ts_get_be16(const uint8_t *p);
uint32_t ts_get_be32(const uint8_t *p);
uint64_t ts_get_be64(const uint8_t *p);
uint16_t ts_get_le16(const uint8_t *p);
uint32_t ts_get_le32(const uint8_t *p);
uint64_t ts_get_le64(const uint8_t *p);

void ts_put_be16(uint8_t *p, uint16_t v);
void ts_put_be32(uint8_t *p, uint32_t v);
void ts_put_be64(uint8_t *p, uint64_t v);
void ts_put_le16(uint8_t *p, uint16_t v);
void ts_put_le32(uint8_t *p, uint32_t v);
void ts_put_le64(uint8_t *p, uint64_t v);

/* Zero n bytes at p; the write is not optimised away. */
void ts_wipe(void *p, size_t n);

#endif
