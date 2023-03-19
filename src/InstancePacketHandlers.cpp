#include "Peer.h"
#include "InstancePackets.h"
#include "InstancePacketHandlers.h"
#include "types.h"
#include "utils.h"

void handle_login(Peer *peer) {
	unsigned char zeroes[64] = { 0 }; // Same thing that we send in S2C_Instance_Info for now
	peer->set_salsa20_creds(zeroes);
}