/**
 * Generate a DSA keypair and save it to files.
 * Code based on https://www.cryptopp.com/wiki/Keys_and_Formats#Downloads
 */

#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

#include <string>
using std::string;

#include <stdexcept>
using std::runtime_error;

#include <cryptopp/queue.h>
using CryptoPP::ByteQueue;

#include <cryptopp/files.h>
using CryptoPP::FileSink;

#include <cryptopp/dsa.h>
using CryptoPP::DSA;

#include <cryptopp/cryptlib.h>
using CryptoPP::PrivateKey;
using CryptoPP::PublicKey;
using CryptoPP::BufferedTransformation;

#include <cryptopp/osrng.h>
using CryptoPP::AutoSeededRandomPool;

void SavePrivateKey(const string& filename, const PrivateKey& key);
void SavePublicKey(const string& filename, const PublicKey& key);
void Save(const string& filename, const BufferedTransformation& bt);

int main(int argc, char** argv)
{
	std::ios_base::sync_with_stdio(false);
	AutoSeededRandomPool rnd;

	try
	{
		// http://www.cryptopp.com/docs/ref/struct_d_s_a.html
		DSA::PrivateKey dsaPrivate;
		dsaPrivate.GenerateRandomWithKeySize(rnd, 2048);

		DSA::PublicKey dsaPublic;
		dsaPrivate.MakePublicKey(dsaPublic);

		SavePrivateKey("dsa-private.key", dsaPrivate);
		SavePublicKey("dsa-public.key", dsaPublic);

		cout << "Successfully generated and saved DSA keys" << endl;
	}

	catch(CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		return -2;
	}

	catch(std::exception& e)
	{
		cerr << e.what() << endl;
		return -1;
	}

	return 0;
}

void SavePrivateKey(const string& filename, const PrivateKey& key)
{
	// http://www.cryptopp.com/docs/ref/class_byte_queue.html
	ByteQueue queue;
	key.Save(queue);

	Save(filename, queue);
}

void SavePublicKey(const string& filename, const PublicKey& key)
{
	// http://www.cryptopp.com/docs/ref/class_byte_queue.html
	ByteQueue queue;
	key.Save(queue);

	Save(filename, queue);
}

void Save(const string& filename, const BufferedTransformation& bt)
{
	// http://www.cryptopp.com/docs/ref/class_file_sink.html
	FileSink file(filename.c_str());

	bt.CopyTo(file);
	file.MessageEnd();
}
