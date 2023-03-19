#include "Peer.h"
#include "InstancePacketHandlers.h"
#include "LoginPacketHandlers.h"
#include "InstancePackets.h"
#include "LoginPackets.h"

ByteBuffer PeerLogin::handle_packet(const std::vector<uint8_t> &data, std::size_t length) {
	ByteBuffer ret;
	if (length < 2) {
		return ret;
	}
	
	u16 opcode = ntohs(*(u16 *)&data[0]);
	switch (opcode) {
	case C2S_HEARTBEAT:
		break;
	case EDH_PUBKEY: {
		C2S_EDH_PubKey *client_key = (C2S_EDH_PubKey *)&data[0];
		ret = handle_edh_pubkey(this, client_key);
		break;
	}
	case C2S_AUTH_DATA:
		handle_auth_data(this);
		break;
	case C2S_PLAY_CHARACTER:
		handle_play_character(this);
		break;
	default:
		printf("Unhandled login opcode: 0x%X\n", opcode);
	}
	
	return ret;
}

ByteBuffer PeerInstance::handle_packet(const std::vector<uint8_t> &data, std::size_t length) {
	ByteBuffer ret;
	if (length < 2) {
		return ret;
	}
	
	u16 opcode = ntohs(*(u16 *)&data[0]);
	switch (opcode) {
	case C2S_LOGIN:
		handle_login(this);
		break;
	default:
		printf("Unhandled instance opcode: 0x%X\n", opcode);
	}
	
	return ret;
}