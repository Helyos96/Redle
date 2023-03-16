#ifndef __H_LOGIN_PACKETS
#define __H_LOGIN_PACKETS

#include <cryptopp/secblock.h>

#include "Packet.h"
#include "types.h"

enum Opcodes : u16 {
	EDH_PUBKEY = 0x02,
	C2S_AUTH_DATA = 0x03,
};

/**
 * Client Diffie-Hellman public number
 */
#pragma pack(push, 1)
struct C2S_EDH_PubKey {
	u16 pid;
	u16 len;
	u8 pub_key[128];
};
#pragma pack(pop)

class S2C_EDH_PubKey : public Packet {
	S2C_EDH_PubKey(const CryptoPP::SecByteBlock &dh_eph_pub_key, const CryptoPP::SecByteBlock &signature, size_t sig_size)
		: Packet(EDH_PUBKEY) {
		buffer << (u16)dh_eph_pub_key.SizeInBytes();
		buffer.append(dh_eph_pub_key.BytePtr(), dh_eph_pub_key.SizeInBytes());
		buffer << (u16)sig_size;
		buffer.append(signature.BytePtr(), sig_size);
	}
};

#endif