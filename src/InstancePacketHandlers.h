#ifndef __H_INSTANCE_PACKET_HANDLERS
#define __H_INSTANCE_PACKET_HANDLERS

#include <vector>

#include "ByteBuffer.h"
#include "InstancePackets.h"
class Peer;

void handle_login(Peer *peer);

#endif