#ifndef __H_INSTANCE_PACKETS
#define __H_INSTANCE_PACKETS

#include "Packet.h"
#include "types.h"

enum OpcodesInstance : u16 {
	C2S_LOGIN = 0x03,
	C2S_CHAT_MESSAGE = 0x08,
	C2S_HNC_CHALLENGE = 0x0E,
	C2S_CLICK_ITEM = 0x1B,
	C2S_ALLOCATE_SKILL_POINT = 0x26,
	C2S_ALLOCATE_ATLAS_SKILL_POINT = 0x2D,
	C2S_BIND_SKILL = 0x3C,
	C2S_USE_FLASK = 0x4F,
	C2S_HASHES = 0x5A,
	C2S_CHANGE_GLOBAL_CHAT = 0xEB,
	C2S_EXIT_CHARACTER_SELECT = 0x108,
	C2S_FINISHED_LOADING = 0x10F, // maybe it's 0x72 or 0x184
	C2S_USE_SKILL = 0x139, // This includes left click
	C2S_MOUSE_DRAGGED = 0x13D,
	C2S_SKILL_RELEASED = 0x13F, // Also includes left click
	C2S_OPEN_WORLD_PANE = 0x145,
	C2S_FINISHED_LOADING_2 = 0x184, // maybe it's 0x72 or 0x10F

	S2C_START_ENCRYPTING = 0x05, // First packet sent. Seems optional.
	S2C_CHAT_MESSAGE = 0x0A,
	S2C_UNK_0x0B = 0x0B,
	S2C_HNC_RESPONSE = 0x0F,
	S2C_AREA_INFO = 0x10,
	S2C_PRELOAD_MONSTER_LIST = 0x13,
	S2C_UNK_0x14 = 0x14, // Last packet before client is done loading
	S2C_PLAYER_ID = 0x15,
	S2C_NEW_INSTANCE_INFO = 0x1A, // Same packet structure as S2C_INSTANCE_INFO (login)
	S2C_UNK_0x25 = 0x25,
	S2C_UNK_0x2C = 0x2C,
	S2C_UNK_0x3A = 0x3A,
	S2C_UNK_0x3F = 0x3F,
	S2C_FRIEND_LIST_ENTRY = 0x75,
	S2C_UNK_0x8B = 0x8B,
	S2C_UNK_0x8C = 0x8C,
	S2C_FRIEND_LIST_ENTRY_2 = 0x95,
	S2C_UNK_0xD5 = 0xD5,
	S2C_UNK_0xEC = 0xEC,
	S2C_UNK_0x14D = 0x14D,
	S2C_PLAYER_ID_2 = 0x185,
	S2C_UNK_0x188 = 0x188,
	S2C_SKILL_GEM = 0x191,
	S2C_UNK_0x1B6 = 0x1B6,
	S2C_TICK = 0x22B,
	S2C_ADD_OBJECT = 0x22F,
};

struct C2S_Hashes {
	u16 opcode;
	u32 tile_hash;
	u32 doodad_hash;
};

class S2C_Area_Info : public Packet {
public:
	S2C_Area_Info() : Packet(S2C_AREA_INFO) {
		buffer << (u16)0x7AD2; // Area Code - 0x7AD2 = The Coast
		buffer << "Standard";
		buffer << (u32)0xF571821F; // seed
		buffer << (u32)0x0100000A;
		buffer << (u8)0x00;
		buffer << (u16)0x6000;
		buffer << (u16)0;
		buffer << (u8)0x01;

		// List of Murmur2 hashes (preload list?)
		buffer << (u16)1; // count
		buffer << (u32)0x2B478CD2;

		buffer << (u16)0x0000;
		buffer << (u16)0x0102;
		buffer << (u16)0x0010;
		buffer << (u16)0x1CF8;
		buffer << (u16)0x36D7;
		buffer << (u16)0x4551;
		buffer << (u16)0x49A6;
		buffer << (u16)0x4C81;
		buffer << (u16)0x7397;
		buffer << (u16)0x7D99;
		buffer << (u16)0x90C1;
		buffer << (u16)0x96D5;
		buffer << (u16)0x9E42;
		buffer << (u16)0xA4BB;
		buffer << (u16)0xB675;
		buffer << (u16)0xD3FD;
		buffer << (u16)0xE6C4;
		buffer << (u16)0xE75E;
		buffer << (u16)0xF217;
	}
};

class S2C_Preload_Monster_List : public Packet {
public:
	S2C_Preload_Monster_List() : Packet(S2C_PRELOAD_MONSTER_LIST) {
		static const size_t len = 0x14;
		static const u8 blob1[len * 2] = { 0xD8, 0x01, 0x4F, 0x04, 0x51, 0x04, 0x53, 0x04, 0xE4, 0x08, 0x5B, 0x0A, 0x5E, 0x0A, 0x60, 0x0A, 0x80, 0x0A, 0x83, 0x0A, 0x9A, 0x0A, 0x55, 0x0C, 0x88, 0x10, 0x8F, 0x10, 0x96, 0x10, 0x52, 0x13, 0x81, 0x17, 0x82, 0x17, 0x83, 0x17, 0x84, 0x17 };
		static const u8 blob2[len] = { 0x02, 0x02, 0x02, 0x02, 0x04, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02 };
		buffer << (u16)len;
		buffer << (u16)0;
		buffer.append(blob1, sizeof(blob1));
		buffer.append(blob2, sizeof(blob2));
	}
};

#define PLAYER_ID 0x0280

class S2C_Player_Id : public Packet {
public:
	S2C_Player_Id() : Packet(S2C_PLAYER_ID) {
		buffer << (u32)PLAYER_ID;
	}
};

class S2C_Player_Id_2 : public Packet {
public:
	S2C_Player_Id_2() : Packet(S2C_PLAYER_ID_2) {
		buffer << (u32)PLAYER_ID;
		buffer << (u32)0;
		buffer << (u16)0;
	}
};

class S2C_Add_Object : public Packet {
public:
	S2C_Add_Object() : Packet(S2C_ADD_OBJECT) {
		buffer << (u32)PLAYER_ID;
		buffer << (u32)0xFFFFFFFF;
		buffer << (u16)0;
		buffer << (u32)0x88527BEE; // Murmur2 hash of "Metadata/Characters/Dex/Dex"
		static const u8 blob[] = { 0x00, 0x00, 0x00, 0xDA, 0x01, 0x00, 0x00, 0xB9, 0x05, 0x00, 0x00, 0x00, 0x00, 0x60, 0x36, 0x01, 0x00, 0x00, 0x37, 0x01, 0x02, 0x03, 0x0E, 0x04, 0x0E, 0x80, 0x8D, 0x01, 0x80, 0xF4, 0x00, 0x80, 0xF5, 0x80, 0x45, 0x80, 0xF6, 0x35, 0x80, 0xF9, 0x38, 0x81, 0x15, 0x00, 0x81, 0x16, 0x00, 0x81, 0x1A, 0x10, 0x81, 0x22, 0x80, 0x42, 0x81, 0x23, 0x80, 0x42, 0x81, 0x24, 0x00, 0x81, 0x25, 0x00, 0x81, 0x45, 0x08, 0x82, 0x3D, 0x0E, 0x82, 0x40, 0x0E, 0x82, 0x43, 0x20, 0x82, 0x9C, 0x00, 0x82, 0x9D, 0x00, 0x82, 0xA2, 0x80, 0x64, 0x82, 0xA3, 0x80, 0x64, 0x83, 0x5D, 0x01, 0x83, 0xAD, 0x00, 0x84, 0x30, 0x00, 0x84, 0xAF, 0x01, 0x84, 0xCD, 0x08, 0x85, 0x88, 0x38, 0x97, 0x76, 0x00, 0x97, 0x77, 0x00, 0x99, 0x1A, 0x01, 0x9C, 0x52, 0x00, 0x9F, 0xE1, 0x01, 0xA0, 0x8A, 0x00, 0xA1, 0x86, 0x83, 0x41, 0xA3, 0xEE, 0x06, 0xA3, 0xEF, 0x05, 0xA3, 0xF1, 0x83, 0x3C, 0xA3, 0xF2, 0x82, 0x7C, 0xA4, 0xA8, 0x80, 0x64, 0xA4, 0xA9, 0x80, 0x64, 0xA7, 0xD5, 0x00, 0xA7, 0xD6, 0x00, 0xA7, 0xD9, 0x00, 0xA7, 0xDA, 0x00, 0xA7, 0xE5, 0x00, 0xA7, 0xE6, 0x00, 0xB6, 0xF8, 0x01, 0xB8, 0x84, 0x00, 0xB9, 0xDC, 0x00, 0xBC, 0x47, 0x0E, 0xBC, 0x48, 0x20, 0xBC, 0x49, 0x0E, 0xC0, 0x42, 0x38, 0x3C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x02, 0x00, 0x02, 0x06, 0x00, 0x08, 0x00, 0x00, 0x00, 0x70, 0x42, 0x00, 0x00, 0x80, 0x3F, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x45, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x35, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x0C, 0x00, 0x00, 0x00, 0x54, 0x00, 0x65, 0x00, 0x73, 0x00, 0x74, 0x00, 0x43, 0x00, 0x68, 0x00, 0x61, 0x00, 0x72, 0x00, 0x61, 0x00, 0x63, 0x00, 0x74, 0x00, 0x65, 0x00, 0x02, 0x0D, 0x02, 0x00, 0x00, 0x21, 0x05, 0xE1, 0xD7, 0x00, 0x00, 0x00, 0x00, 0x0C, 0x00, 0x03, 0x28, 0x40, 0x00, 0x80, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x04, 0x00, 0x80, 0x00, 0x38, 0x03, 0x00, 0x00, 0x00, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x07, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x02, 0x80, 0x01, 0x00, 0x08, 0x00, 0x00, 0x28, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x0D, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x1B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x80, 0x00, 0x1D, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1F, 0x00, 0x00, 0x00, 0x00, 0x10, 0x04, 0x00, 0x00, 0x28, 0xF0, 0xFF, 0x3F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x00, 0x94, 0x09, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x10, 0x00, 0x00, 0x38, 0x42, 0x90, 0x00, 0x15, 0x02, 0xF0, 0xFF, 0xFF, 0xFA, 0xEF, 0xE7, 0x5E, 0xBD, 0x03, 0xE3, 0x05, 0x00, 0x00, 0x38, 0x00, 0x00, 0x08, 0x04, 0xE0, 0xFF, 0x7F, 0x7F, 0xE6, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x28, 0x03, 0x00, 0x30, 0x00, 0x06, 0x00, 0x00, 0x80, 0x01, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0xFF, 0xD9, 0xBF, 0x83, 0x61, 0x09, 0x06, 0xF8, 0xFA, 0x23, 0x00, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0B, 0x00, 0x00, 0x00, 0x20, 0x00, 0x04, 0x00, 0x00, 0x0D, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x11, 0xF8, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xE0, 0xED, 0x03, 0x00, 0x1D, 0xFB, 0x00, 0x00, 0xFF, 0x7B, 0x03, 0x40, 0x1A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x01, 0x00, 0x40, 0x00, 0xB1, 0x09, 0x00, 0x00, 0x00, 0xB3, 0x09, 0x00, 0x00, 0x00, 0x00, 0x0D, 0x81, 0x5C, 0x01, 0x82, 0xA4, 0x80, 0x78, 0x82, 0xA5, 0x00, 0x83, 0x52, 0x01, 0x85, 0xC7, 0x01, 0x87, 0xCB, 0x00, 0x87, 0xCC, 0x00, 0x8B, 0x77, 0x01, 0x8B, 0x78, 0x80, 0x64, 0x9D, 0xE8, 0x01, 0x9F, 0xA4, 0x01, 0xA4, 0x2D, 0x83, 0xE8, 0xC0, 0x40, 0x76, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00 };
		buffer << (u16)sizeof(blob);
		buffer.append(blob, sizeof(blob));
	}
};

class S2C_Skill_Gem : public Packet {
public:
	S2C_Skill_Gem() : Packet(S2C_SKILL_GEM) {
		buffer << (u32)5;
		buffer << (u32)36;
		buffer << (u32)0x6B6943FF; // Murmur2 hash of "Metadata/Items/Gems/SkillGemShieldCharge"
		buffer << (u32)0;
		buffer << (u64)0;
		buffer << (u8)0x04;
		buffer << (u32)0xFFFFFFFF;
	}
};

class S2C_Unk_0x1B6 : public Packet {
public:
	S2C_Unk_0x1B6() : Packet(S2C_UNK_0x1B6) {
		buffer << (u8)1;
		buffer << (u8)1;
		buffer << (u8)0;
	}
};

class S2C_Hnc_Response : public Packet {
public:
	S2C_Hnc_Response(u16 arg1, u32 arg2) : Packet(S2C_HNC_RESPONSE) {
		buffer << arg1;
		buffer << arg2;
	}
};

class S2C_Unk_0xD5 : public Packet {
public:
	S2C_Unk_0xD5() : Packet(S2C_UNK_0xD5) {
		buffer << (u16)0;
	}
};

class S2C_Unk_0x188 : public Packet {
public:
	S2C_Unk_0x188() : Packet(S2C_UNK_0x188) {
		buffer << (u16)0;
	}
};

class S2C_Unk_0x8B : public Packet {
public:
	S2C_Unk_0x8B() : Packet(S2C_UNK_0x8B) {
		buffer << (u8)0;
		buffer << (u32)1; // Same ID as in 0x8C packets
		buffer << (u32)0;
		buffer << (u32)0;
		buffer << (u32)0;
		buffer << (u8)1;
		buffer << (u32)2;
		buffer << (u32)0;
		buffer << (u32)3;
		buffer << (u32)2;
	}
};

class S2C_Unk_0x8C : public Packet {
public:
	S2C_Unk_0x8C() : Packet(S2C_UNK_0x8C) {
		buffer << (u8)0;
		buffer << (u32)1; // Some kind of incrementing ID
		buffer << (u8)0;
		buffer << (u8)0;
		buffer << (u8)0x0C;
		buffer << (u8)0x05;
		buffer << (u8)0;
		buffer << (u32)0;
		buffer << (u16)0;
	}
};

class S2C_Unk_0xEC : public Packet {
public:
	S2C_Unk_0xEC(u16 arg2) : Packet(S2C_UNK_0xEC) {
		buffer << (u16)2;
		buffer << (u16)arg2;
	}
};

class S2C_Unk_0x14 : public Packet {
public:
	S2C_Unk_0x14() : Packet(S2C_UNK_0x14) {
		buffer << (u16)0; // Entry count

		// Entries (contains strings like "Bases", "Expedition", "Leagues"). Maybe account state?
		// For now we just send 0 entries.

		// Ending
		buffer << (u16)0;
		buffer << (u8)0x68;
		buffer << (u8)0x40;
		buffer << (u8)0x0;
		buffer << (u8)0x0;
	}
};

class S2C_Unk_0x25 : public Packet {
public:
	S2C_Unk_0x25() : Packet(S2C_UNK_0x25) {
		buffer << (u16)0;
		buffer << (u16)0;
		buffer << (u16)0;
		buffer << (u8)2;
		buffer << (u8)2;
		buffer << (u8)1;
		buffer << (u16)0;
		buffer << (u16)0;
		buffer << (u16)0;
		buffer << (u16)0;
	}
};

class S2C_Unk_0x2C : public Packet {
public:
	S2C_Unk_0x2C() : Packet(S2C_UNK_0x2C) {
		buffer << (u16)0;
		buffer << (u16)2;
		buffer << (u8)0;
		buffer << (u16)0;
	}
};

class S2C_Unk_0x3A : public Packet {
public:
	S2C_Unk_0x3A() : Packet(S2C_UNK_0x3A) {
		buffer << (u32)0;
		u8 blob[] = { 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		buffer.append(blob, sizeof(blob));
	}
};

class S2C_Unk_0x3F : public Packet {
public:
	S2C_Unk_0x3F() : Packet(S2C_UNK_0x3F) {
		u8 blob[] = { 0x09, 0x29, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		buffer.append(blob, sizeof(blob));
		buffer << (u16)0;
		buffer << (u16)0;
	}
};

class S2C_Unk_0x14D : public Packet {
public:
	S2C_Unk_0x14D() : Packet(S2C_UNK_0x14D) {
		buffer << (u8)0 << (u8)0 << (u8)0 << (u8)0x37 << (u8)0;
		u8 blob[] = { 0x00, 0x02, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		buffer.append(blob, sizeof(blob));
		buffer.append(blob, sizeof(blob));
		buffer.append(blob, sizeof(blob));
		u8 blob2[] = { 0x00, 0x00, 0x11, 0x00, 0x16, 0x00, 0x00, 0x00, 0x1B, 0x00, 0x10, 0x00, 0x03, 0x00 };
		buffer.append(blob2, sizeof(blob2));
		u8 blob3[] = { 0x00, 0x00, 0x04, 0x00, 0x06, 0x00, 0x00, 0x00, 0x06, 0x00, 0x06, 0x00, 0x02, 0x00 };
		buffer.append(blob3, sizeof(blob3));
		u8 blob4[] = { 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		buffer.append(blob4, sizeof(blob4));
		buffer << (u8)0;
	}
};

class S2C_Unk_0x0B : public Packet {
public:
	S2C_Unk_0x0B() : Packet(S2C_UNK_0x0B) {
		buffer << (u16)0x78;
		buffer << (u16)0xFFFF;
		buffer << (u16)0x0200;
		buffer << (u32)0;
		buffer << (u8)1;
		buffer << (u8)0;
		buffer << (u8)7;
		buffer << (u32)4;
	}
};


#endif