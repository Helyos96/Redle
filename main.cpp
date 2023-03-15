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

#define DEFAULT_BUFLEN 512
#define DEFAULT_PORT "20481"
#define LOGIN_PORT 20481

class tcp_server {
public:
	tcp_server(asio::io_context& io_context) : io_context_(io_context),
		acceptor_(io_context, tcp::endpoint(tcp::v4(), LOGIN_PORT)) {
		start_accept();
	}

private:
	void start_accept() {
		Peer::pointer new_connection = Peer::create(io_context_);

		acceptor_.async_accept(new_connection->socket(),
			std::bind(&tcp_server::handle_accept, this, new_connection, std::placeholders::_1));
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
		tcp_server server(io_context);
		io_context.run();
	} catch (std::exception& e) {
		std::cerr << e.what() << std::endl;
	}

  return 0;
}