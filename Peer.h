#ifndef __H_PEER
#define __H_PEER

#include <cryptopp/salsa.h>
#include <vector>
#include <cstdint>

class Peer {
public:
	enum Status {
		None,
		CryptoSetup,
		LoggedIn,
	};
	
	Peer(SOCKET socket) : socket(socket), status(None) {}

	void set_salsa20_creds(const unsigned char *buf) {
		enc.SetKeyWithIV(buf, 32, buf + 40, 8);
		dec.SetKeyWithIV(buf, 32, buf + 32, 8);
		status = CryptoSetup;
	}
	
	std::vector<uint8_t> decrypt_packet(const unsigned char *raw_packet, size_t len) {
		std::vector<uint8_t> ret;
		ret.resize(len);
		dec.ProcessData(&ret[0], raw_packet, len);
		return ret;
	}
	
	SOCKET socket;
	Status status;

protected:
	CryptoPP::Salsa20::Encryption enc;
	CryptoPP::Salsa20::Decryption dec;
	
};

#endif