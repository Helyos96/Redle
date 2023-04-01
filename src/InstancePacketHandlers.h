#ifndef __H_INSTANCE_PACKET_HANDLERS
#define __H_INSTANCE_PACKET_HANDLERS

#include <vector>

#include "ByteBuffer.h"
#include "InstancePackets.h"
class Peer;

void handle_instance_login(Peer *peer);
void handle_hashes(Peer *peer);
void handle_finished_loading(Peer *peer);
void handle_hnc_challenge(Peer *peer);

#endif