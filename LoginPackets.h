#ifndef __H_LOGIN_PACKETS
#define __H_LOGIN_PACKETS

#include <cstdint>

enum Opcodes {
	EDH_PUBKEY = 0x02,
	C2S_AUTH_DATA = 0x03,
};

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

#endif