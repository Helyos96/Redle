#ifndef __H_LOGIN_PACKETS
#define __H_LOGIN_PACKETS

#include <cryptopp/secblock.h>

#include "Packet.h"
#include "types.h"

enum Opcodes : u16 {
	C2S_HEARTBEAT = 0x01,
	EDH_PUBKEY = 0x02,
	C2S_AUTH_DATA = 0x03,
	C2S_CHANGE_PASSWORD = 0x09,
	C2S_DELETE_CHARACTER = 0x0B,
	C2S_PLAY_CHARACTER = 0x0D,
	C2S_CREATE_CHARACTER = 0x11,
	C2S_LEAGUE_MIGRATIONS = 0x17,

	S2C_UNK_0x04 = 0x04,
	S2C_INSTANCE_INFO = 0x13,
	S2C_CHARACTER_LIST = 0x14,
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
	S2C_Char_List() : Packet(S2C_CHARACTER_LIST) {
		buffer << (u8)1; // Character count

		buffer << "TestChar";
		buffer << "Standard";
		buffer << (u16)0x0204;
		buffer << (u8)100; // level
		buffer << (u8)0xB9;
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
	S2C_League_List() : Packet(S2C_LEAGUE_LIST) {
		buffer << (u64)0x520d166400000000;
		buffer << (u32)1; // League count

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
	S2C_Unk_0x04() : Packet(S2C_UNK_0x04) {
		buffer << (u16)0;
		buffer << (u16)0;
		u8 zeros[32] = { 0 };
		buffer.append(zeros, sizeof(zeros));
		buffer << (u8)0x22;
		buffer << "AccountName";
	}
};

class S2C_Instance_Info : public Packet {
public:
	S2C_Instance_Info() : Packet(S2C_INSTANCE_INFO) {
		buffer << (u32)0x00000001; // Token? Echoed in OpcodesInstance::C2S_LOGIN
		buffer << (u16)0x235C;
		buffer << (u32)0x00000002; // Another Token? Echoed in OpcodesInstance::C2S_LOGIN
		buffer << (u8)1;
		buffer << (u16)0x200;
		buffer << (u16)6112; // port
		buffer << (u32)0x7F000001; // IPv4 127.0.0.1
		u8 zeros[20] = { 0 };
		buffer.append(zeros, sizeof(zeros));
		// New SHA512 to derive Salsa20 key+IVs to communicate with gameserver? If 0 it seems to disable encryption
		u8 sha512[64] = { 0 };
		buffer.append(sha512, sizeof(sha512));
	}
};

#endif