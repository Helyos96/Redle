#ifndef __H_LOGIN_PACKETS
#define __H_LOGIN_PACKETS

#include <cryptopp/secblock.h>

#include "Packet.h"
#include "types.h"

enum Opcodes : u16 {
	EDH_PUBKEY = 0x02,
	C2S_AUTH_DATA = 0x03,
	S2C_UNK_0x04 = 0x04,
	S2C_CHAR_LIST = 0x14,
	S2C_LEAGUE_LIST = 0x19
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
public:
	S2C_EDH_PubKey(const CryptoPP::SecByteBlock &dh_eph_pub_key, const CryptoPP::SecByteBlock &signature, size_t sig_size)
		: Packet(EDH_PUBKEY) {
		buffer << (u16)dh_eph_pub_key.SizeInBytes();
		buffer.append(dh_eph_pub_key.BytePtr(), dh_eph_pub_key.SizeInBytes());
		buffer << (u16)sig_size;
		buffer.append(signature.BytePtr(), sig_size);
	}
};

class S2C_Char_List : public Packet {
public:
	S2C_Char_List()
		: Packet(S2C_CHAR_LIST) {
		buffer << (u8)1; // Amount of characters
		buffer << "TestChar";
		buffer << "Standard";
		buffer << (u32)0x020460b9;
		buffer << (u32)0xa2bd34c4;
		buffer << (u16)0;
		buffer << (u16)0;
		buffer << (u16)0;
		
		buffer << (u16)0x0c18;
		buffer << (u16)0;
	}
};

class S2C_League_List : public Packet {
public:
	S2C_League_List()
		: Packet(S2C_LEAGUE_LIST) {
		buffer << (u64)0x520d166400000000;
		buffer << (u32)1; // league amount?

		buffer << "Standard";
		buffer << "#LeagueStandard";
		buffer << (u16)0; // Parent league
		buffer << (u16)0; // Unk optional string
		buffer << (u16)0; // Short Name
		buffer << (u64)0x504F005100000000;
		buffer << (u64)0xB0AC725D00000000;
		buffer << (u64)0;
		buffer << (u8)0xA8;
		buffer << (u16)0;
		buffer << (u16)1;

		buffer << (u8)0;
	}
};

class S2C_Unk_0x04 : public Packet {
public:
	S2C_Unk_0x04()
		: Packet(S2C_UNK_0x04) {
		buffer << (u16)0;
		buffer << (u16)0;
		u8 zeros[32] = { 0 };
		buffer.append(zeros, sizeof(zeros));
		buffer << (u8)0x22;
		buffer << "AccountName";
	}
};

#endif