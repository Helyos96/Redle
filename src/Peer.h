#ifndef __H_PEER
#define __H_PEER

#include <cryptopp/salsa.h>
#include <vector>
#include <cstdint>

#define _WIN32_WINNT 0x0601
#include "asio.hpp"
using asio::ip::tcp;

#include "Packet.h"
#include "utils.h"

class PeerLogin;
extern PeerLogin *peerPtr;

class Peer : public std::enable_shared_from_this<Peer> {
public:
	enum Status {
		None,
		CryptoSetup,
		LoggedIn,
	};

	tcp::socket& socket() {
		return socket_;
	}

	void start() {
		do_read();
	}

	void set_salsa20_creds(const unsigned char *buf) {
		enc_.SetKeyWithIV(buf, 32, buf + 48, 8);
		dec_.SetKeyWithIV(buf, 32, buf + 32, 8);
		status_ = CryptoSetup;
	}
	
	void send_packet(Packet &packet) {
		std::vector<uint8_t> raw_packet;
		printf("[%s] Server -> Client (%zu)\n", server_type, packet.size());
		printPacket(packet.data(), packet.size());
		if (status_ != None) {
			raw_packet = encrypt_packet(packet.data(), packet.size());
		} else {
			raw_packet.insert(raw_packet.end(), packet.data(), packet.data() + packet.size());
		}
		asio::async_write(socket_, asio::buffer(raw_packet.data(), raw_packet.size()),
			[/*this, self*/](std::error_code /*ec*/, std::size_t /*length*/) {
			});
	}

protected:
	Peer(asio::io_context& io_context, const char *server_type) : socket_(io_context), server_type(server_type), status_(None) {
	}

	std::vector<uint8_t> decrypt_packet(const unsigned char *raw_packet, size_t len) {
		std::vector<uint8_t> ret;
		ret.resize(len);
		dec_.ProcessData(&ret[0], raw_packet, len);
		return ret;
	}

	std::vector<uint8_t> encrypt_packet(const unsigned char *raw_packet, size_t len) {
		std::vector<uint8_t> ret;
		ret.resize(len);
		enc_.ProcessData(&ret[0], raw_packet, len);
		return ret;
	}

	virtual ByteBuffer handle_packet(const std::vector<uint8_t> &data, std::size_t length) = 0;

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
					printf("[%s] Client -> Server (%zu)\n", server_type, packet.size());
					printPacket(packet.data(), packet.size());
					auto to_send = handle_packet(packet, length);
					if (to_send.size() > 0) {
						asio::async_write(socket_, asio::buffer(to_send.contents(), to_send.size()),
							[/*this, self*/](std::error_code /*ec*/, std::size_t /*length*/) {
							});
					}
					do_read();
				} else {
					printf("Error reading: %u (size %zu)\n", ec.value(), length);
					socket_.close();
				}
			}
		);
	}

	enum { max_length = 8192 };

	const char *server_type;
	tcp::socket socket_;
	unsigned char data_[max_length];
	Status status_;
	CryptoPP::Salsa20::Encryption enc_;
	CryptoPP::Salsa20::Decryption dec_;
};

class PeerLogin : public Peer {
public:
	typedef std::shared_ptr<Peer> pointer;
	static pointer create(asio::io_context& io_context) {
		peerPtr = new PeerLogin(io_context);
		return pointer(peerPtr);
	}
	void send_final() {
		if (status_ == LoggedIn) {
			printf("[LOGIN] Sending Disconnect Packet\n");
			const u8 data[] = { 0x00, 0x14 };
			Packet unk_15(0x15, data, sizeof(data));
			std::vector<uint8_t> raw_packet = encrypt_packet(unk_15.data(), unk_15.size());
			//auto self(shared_from_this());
			asio::async_write(socket_, asio::buffer(raw_packet.data(), raw_packet.size()),
				[/*this, self*/](std::error_code ec, std::size_t length) {
					printf("ec = %d length = %zu\n", ec.value(), length);
			});
			status_ = None;
		} else {
			printf("[LOGIN] Closing Socket\n");
			socket_.close();
		}
	}
	void login(u32 account_id) {
		status_ = LoggedIn;
		printf("%p: status = %u\n", this, status_);
		account_id_ = account_id;
		peerPtr = this;
	}
	u32 get_account_id() { return account_id_; }
protected:
	PeerLogin(asio::io_context& io_context) : Peer(io_context, "LOGIN"), account_id_(0) {
	}
	ByteBuffer handle_packet(const std::vector<uint8_t> &data, std::size_t length) override;
	u32 account_id_;
};

class PeerInstance : public Peer {
public:
	typedef std::shared_ptr<Peer> pointer;
	static pointer create(asio::io_context& io_context) {
		return pointer(new PeerInstance(io_context));
	}
protected:
	PeerInstance(asio::io_context& io_context) : Peer(io_context, "INSTANCE") {
	}
	ByteBuffer handle_packet(const std::vector<uint8_t> &data, std::size_t length) override;
};

#endif