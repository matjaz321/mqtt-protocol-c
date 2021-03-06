#ifndef PACK_H
#define PACK_H

#include <stdio.h>
#include <stdint.h>

// Bytes to unit_8t
uint8_t unpack_u8(const uint8_t **);
// Converting bytes to uint16_t
uint16_t unpack_u16(const uint8_t **);
// Converting bytes to unit_32_t
uint32_t unpack_u32(const uint8_t **);
// Unpacking bytes
uint8_t *unpack_bytes(const uint8_t **, size_t, uint8_t *);

// Appending data to bytestream
void pack_u8(uint8_t **, uint8_t);
void pack_u16(uint8_t **, uint16_t);
void pack_u32(uint8_t **, uint32_t);
void pack_bytes(uint8_t **, uint8_t *);

#endif //PACK_H
