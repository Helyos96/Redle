#ifndef __H_PACKET
#define __H_PACKET

#include "ByteBuffer.h"
#include "types.h"

class Packet {
public:
	Packet(u16 opcode) {
		buffer << opcode;
	}
protected:
	ByteBuffer buffer;
};

#endif