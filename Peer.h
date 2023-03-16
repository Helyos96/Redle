#ifndef __H_PEER
#define __H_PEER

#include <cryptopp/salsa.h>
#include <vector>
#include <cstdint>

#define _WIN32_WINNT 0x0601
#include "asio.hpp"
using asio::ip::tcp;

#include "PacketHandlers.h"
#include "utils.h"

class Peer : public std::enable_shared_from_this<Peer> {
public:
	typedef std::shared_ptr<Peer> pointer;
	enum Status {
		None,
		CryptoSetup,
		LoggedIn,
	};

	static pointer create(asio::io_context& io_context) {
		return pointer(new Peer(io_context));
	}

	tcp::socket& socket() {
		return socket_;
	}
	
	void start() {
		do_read();
	}
	
	void set_salsa20_creds(const unsigned char *buf) {
		enc_.SetKeyWithIV(buf, 32, buf + 40, 8);
		dec_.SetKeyWithIV(buf, 32, buf + 32, 8);
		status_ = CryptoSetup;
	}

private:
	Peer(asio::io_context& io_context) : socket_(io_context), status_(None) {
	}

	std::vector<uint8_t> decrypt_packet(const unsigned char *raw_packet, size_t len) {
		std::vector<uint8_t> ret;
		ret.resize(len);
		dec_.ProcessData(&ret[0], raw_packet, len);
		return ret;
	}

	void do_read()
	{
		auto self(shared_from_this());
		socket_.async_read_some(asio::buffer(data_, max_length),
			[this, self](std::error_code ec, std::size_t length) {
				
				if (!ec) {
					std::vector<uint8_t> packet;
					if (status_ != None) {
						packet = decrypt_packet(data_, length);
					} else {
						packet.insert(packet.end(), data_, data_ + length);
					}
					printPacket(packet.data(), packet.size());
					auto to_send = handle_packet(this, packet, length);
					if (to_send.size() > 0) {
						asio::async_write(socket_, asio::buffer(to_send.contents(), to_send.size()),
							[this, self](std::error_code ec, std::size_t /*length*/) {
								if (!ec) {
									do_read();
								}
							});
					} else {
						do_read();
					}
				}
			}
		);
	}

	enum { max_length = 8192 };

	tcp::socket socket_;
	unsigned char data_[max_length];
	Status status_;
	CryptoPP::Salsa20::Encryption enc_;
	CryptoPP::Salsa20::Decryption dec_;
};

#endif