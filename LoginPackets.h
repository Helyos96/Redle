#ifndef __H_LOGIN_PACKETS
#define __H_LOGIN_PACKETS

#include <cstdint>

/**
 * Client Diffie-Hellman public number
 */
#pragma pack(push, 1)
struct C2S_EDH_PubKey {
	uint16_t pid;
	uint16_t len;
	uint8_t pub_key[128];
};
#pragma pack(pop)

/**
 * Server Diffie-Hellman public number
 * + 2048-bit DSA Signature (which turns out is only 56-byte long)
 */
#pragma pack(push, 1)
struct S2C_EDH_PubKey_Sig {
	uint16_t pid;
	uint16_t len;
	uint8_t pub_key[128];
	uint16_t len_sig;
	uint8_t sig[56];
};
#pragma pack(pop)

#endif