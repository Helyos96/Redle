#ifndef __H_PACKET
#define __H_PACKET

#include "ByteBuffer.h"
#include "types.h"

class Packet {
public:
	Packet(u16 opcode) : opcode_(opcode) {
		buffer << opcode;
	}

	Packet(u16 opcode, const u8 *buf, size_t len) : opcode_(opcode) {
		buffer << opcode;
		buffer.append(buf, len);
	}

	u8* data() { return buffer.contents(); }
	size_t size() const { return buffer.size(); }
	u16 opcode() { return opcode_; }

protected:
	ByteBuffer buffer;
	u16 opcode_;
};

#endif