#ifndef __H_PACKET_HANDLERS
#define __H_PACKET_HANDLERS

#include <vector>

class Peer;
std::vector<uint8_t> handle_packet(Peer *peer, const std::vector<uint8_t> &data, size_t length);

#endif