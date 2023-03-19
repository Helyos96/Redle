#ifndef __H_LOGIN_PACKET_HANDLERS
#define __H_LOGIN_PACKET_HANDLERS

#include <vector>

#include "ByteBuffer.h"
#include "LoginPackets.h"
class Peer;

ByteBuffer handle_edh_pubkey(Peer *peer, const C2S_EDH_PubKey *client_key);
void handle_auth_data(Peer *peer);
void handle_play_character(Peer *peer);

#endif