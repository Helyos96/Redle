#include <iostream>
#include <functional>
#include <memory>

#include <stdlib.h>
#include <stdio.h>

#define _WIN32_WINNT 0x0601
#include "asio.hpp"

#include "Peer.h"
#include "utils.h"

using asio::ip::tcp;

#define LOGIN_PORT 20481
#define INSTANCE_PORT 6112

class tcp_instance_server {
public:
	tcp_instance_server(asio::io_context& io_context) : io_context_(io_context),
		acceptor_(io_context, tcp::endpoint(tcp::v4(), INSTANCE_PORT)) {
		start_accept();
	}

private:
	void start_accept() {
		Peer::pointer new_connection = Peer::create(io_context_);

		acceptor_.async_accept(new_connection->socket(),
			std::bind(&tcp_instance_server::handle_accept, this, new_connection, std::placeholders::_1));
	}

	void handle_accept(Peer::pointer new_connection, const asio::error_code& error) {
		if (!error) {
			unsigned char zeroes[64] = { 0 }; // Same thing that we send in S2C_Instance_Info for now
			new_connection->set_salsa20_creds(zeroes);
			new_connection->start();
		}
		start_accept();
	}

	asio::io_context& io_context_;
	tcp::acceptor acceptor_;
};

class tcp_login_server {
public:
	tcp_login_server(asio::io_context& io_context) : io_context_(io_context),
		acceptor_(io_context, tcp::endpoint(tcp::v4(), LOGIN_PORT)) {
		start_accept();
	}

private:
	void start_accept() {
		Peer::pointer new_connection = Peer::create(io_context_);

		acceptor_.async_accept(new_connection->socket(),
			std::bind(&tcp_login_server::handle_accept, this, new_connection, std::placeholders::_1));
	}

	void handle_accept(Peer::pointer new_connection, const asio::error_code& error) {
		if (!error) {
			new_connection->start();
		}
		start_accept();
	}

	asio::io_context& io_context_;
	tcp::acceptor acceptor_;
};

int main(void) {
	try {
		asio::io_context io_context;
		tcp_login_server server_login(io_context);
		tcp_instance_server server_instance(io_context);
		io_context.run();
	} catch (std::exception& e) {
		std::cerr << e.what() << std::endl;
	}

  return 0;
}