#include <cryptopp/integer.h>
#include <cryptopp/dh.h>
#include <cryptopp/dh2.h>
#include <cryptopp/osrng.h>
#include <cryptopp/nbtheory.h>
#include <cryptopp/files.h>
#include <iostream>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>

#include "Peer.h"
#include "LoginPackets.h"

using namespace std;
using namespace CryptoPP;

#define DEFAULT_BUFLEN 512
#define DEFAULT_PORT "20481"

/*const static char* key_1 = "0x266EAF63CD8CBBD3210AA28AB242F2F9FDC8B9A1EA59AE3F495B6006EBCB6BDEB9F06DAE7DC11D1DF90E05AB338BA73BC1F712CD697A87259FD22BBE5580484FA6820560D9CAEFF0D6793C8E7470FA9042B268210DEB31D746A2687DEE573FD05EE2DBA4FBE4C695A83FDCC08CAFD23FDC1FE2B3241877D5F5992BDF5BE80B09";
const static char* key_2 = "0x8808D4D3D3F46EEF5559D597B02276D3E97441C936CB8E444BF81828C32B4936A930E3ABD5769C341AFED9F587B34FC446D629B5F5DC99927780250717307FB42F48EE465545A2EBC3A7AFD8E55BFA79D8F77B068E55B85998C90E1EE9F9EEB6A5D17E225350118F39F650B87EE466C3BE8B87261CCABD3D5334547D0EB24FA9";
const static char* key_3 = "0x33A1AA9711E6E28CC28DE17DC44EC3784C60FB2E7A3A5034BAA92967840BBFFE9717677DA46A08EF314D9B5B9E3A003D2AF2EE429B7BFCEBC75341240E61CDCD8D7DC90F839BA53F9B159E3FC06BD271EF06CDB32BFA62A52A747155F4ADA711DB010C1D04D2BB1BA1D13C400FE75B1893E89F22166EBB01CFBEF81150D39CB0";*/
//const static char* client_priv_key = "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000A400F5D71DEFF86AC2F7E2BD1B41AB1EB100CDE79ECD9E833A22686AB496BE09D3A";

void Load(const string& filename, BufferedTransformation& bt)
{
	FileSource file(filename.c_str(), true /*pumpAll*/);

	file.TransferTo(bt);
	bt.MessageEnd();
}

void LoadPrivateKey(const string& filename, PrivateKey& key)
{
	ByteQueue queue;

	Load(filename, queue);
	key.Load(queue);	
}

void printPacket(const uint8_t *buffer, uint32_t size)
{
#define ppMIN(a, b)       ((a) < (b) ? (a) : (b))
	char* stringbuffer = new char[size+2048]; // 256 bytes for the message around it.
	memset(stringbuffer, 0, (size + 2048 )* sizeof(char));

	unsigned int i;
	sprintf(stringbuffer + strlen(stringbuffer), "Printing packet with size %u\n", size);
   
	for(i = 0; i < size; ++i) {
		if(i != 0&& i%16 == 0) {
			for(unsigned int j = i-16; j < i; ++j) {
				if(buffer[j] >= 32 && buffer[j] <= 126)
					sprintf(stringbuffer + strlen(stringbuffer), "%c", buffer[j]);
				else
					sprintf(stringbuffer + strlen(stringbuffer), ".");
			}

			sprintf(stringbuffer + strlen(stringbuffer), "\n");
		}

		if(i%16 == 0) {
			sprintf(stringbuffer + strlen(stringbuffer), "%04d-%04d ", i, ppMIN(i + 15, size - 1));
		}

		sprintf(stringbuffer + strlen(stringbuffer), "%02X ", buffer[i]);
	}
   
	for(i = ((16-i%16)%16); i > 0; --i)
		sprintf(stringbuffer + strlen(stringbuffer), "   ");
   
	for(i = size- (size%16 == 0 ? 16 : size%16); i < size; ++i) {
		if(buffer[i] >= 32 && buffer[i] <= 126)
			sprintf(stringbuffer + strlen(stringbuffer), "%c", buffer[i]);
		else
			sprintf(stringbuffer + strlen(stringbuffer), ".");
	}
   
	sprintf(stringbuffer + strlen(stringbuffer), "\r\n");

	printf("%s", stringbuffer);
	delete[] stringbuffer;
}

static const unsigned char serv_dh_static_priv[] =  { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0B, 0x73, 0x36, 0x17, 0x4E, 0x76, 0xE5, 0x18, 0xB2, 0x0F, 0x08, 0xD5, 0xF6, 0x53, 0x13, 0x8F, 0xC3, 0x90, 0x33, 0x3D, 0x32, 0xEA, 0x3D, 0x1B, 0x38, 0xA2, 0x07, 0x77, 0x85, 0x20, 0x16, 0x71, 0x7F, 0x54 };
static const unsigned char client_dh_static_pub[] = { 0x01, 0x78, 0x01, 0x37, 0xEE, 0x61, 0x81, 0xD3, 0x74, 0x79, 0x32, 0xC1, 0x1F, 0x86, 0xDD, 0xBC, 0xC0, 0x82, 0x1C, 0x06, 0x1C, 0xC3, 0x71, 0xEA, 0x0C, 0x6A, 0xC2, 0xDE, 0x62, 0xAE, 0xAC, 0xE7, 0x1C, 0xF1, 0x56, 0x0E, 0xEF, 0xAA, 0xFC, 0x03, 0xF0, 0xA1, 0x3B, 0x2C, 0xFA, 0x10, 0x64, 0xD7, 0x12, 0x0B, 0x8F, 0x6E, 0x28, 0xCA, 0x3E, 0x16, 0xE3, 0xA3, 0xC0, 0x56, 0xF4, 0x33, 0x9E, 0xD1, 0x12, 0xA0, 0xF3, 0x11, 0x98, 0xE5, 0xC4, 0x4E, 0x7D, 0xA1, 0xD2, 0x7F, 0xFE, 0xB5, 0x17, 0xAD, 0x7F, 0x24, 0xCE, 0xF7, 0x92, 0xAE, 0x1B, 0x11, 0x92, 0x2F, 0x93, 0x31, 0x6F, 0x30, 0xF1, 0x0E, 0x1F, 0x3A, 0x4D, 0xD3, 0x83, 0xC3, 0x0E, 0x30, 0xD7, 0xAC, 0x52, 0xC8, 0x34, 0x33, 0x41, 0x55, 0x1F, 0x6E, 0xC6, 0x5F, 0x27, 0x10, 0xBF, 0xE2, 0x7B, 0x54, 0xD9, 0x0F, 0xFD, 0x4F, 0x8A, 0x69, 0x27, 0x61, 0x4E, 0x1A, 0x51, 0x98, 0xAB, 0xA6, 0xEB, 0x1D, 0xE3, 0x34, 0x88, 0x54, 0xF0, 0xAA, 0xC0, 0x40, 0x6F, 0xDF, 0xBB, 0xF8, 0xF9, 0x05, 0x05, 0x5D, 0xA3, 0x41, 0x08, 0x85, 0x36, 0xA2, 0x74, 0x06, 0xF6, 0x93, 0xF6, 0x2B, 0x46, 0xD2, 0x5E, 0xD8, 0xFA, 0xDD, 0x97, 0x1D, 0x96, 0x94, 0x0F, 0x23, 0xCC, 0xEE, 0xC7, 0xA9, 0xDE, 0xF8, 0xD9, 0x63, 0x5A, 0x74, 0x4D, 0x9F, 0x2F, 0xF7, 0x0C, 0xD7, 0xA6, 0x73, 0x41, 0xA6, 0xD2, 0x65, 0x32, 0xD9, 0x40, 0xEE, 0x08, 0xF3, 0xC5, 0x38, 0x8E, 0xD9, 0x3D, 0xA9, 0x78, 0x5C, 0x87, 0xB7, 0x78, 0x4B, 0xC9, 0xDA, 0xBF, 0x8E, 0x9C, 0x61, 0x61, 0xB2, 0xB1, 0xFB, 0x4E, 0x20, 0x85, 0x8D, 0x33, 0x9F, 0x1F, 0x42, 0xDF, 0xB9, 0x1D, 0xAD, 0xC1, 0x2B, 0x8F, 0xD6, 0x58, 0xA2, 0x8C, 0x4F, 0x67, 0xFE, 0xC0, 0xC0, 0x03, 0x62, 0x49, 0x51, 0x0A, 0x8E, 0x7F, 0x13, 0x8D, 0xEB, 0xBC, 0x70, 0x33, 0xB3, 0xA0, 0x29, 0x83, 0x09, 0x08, 0xC9, 0xDF, 0xFB, 0xE9, 0xB6, 0x00, 0xB4, 0x6A, 0x5B, 0x15, 0xF1, 0xF4, 0xF8, 0xA3, 0xD9, 0xC2, 0xFB, 0x34, 0x67, 0x59, 0x95, 0xFC, 0x2A, 0xC3, 0x1F, 0x83, 0x4F, 0x95, 0xD5, 0xC9, 0x8B, 0xFC, 0x3B, 0xE2, 0x59, 0xBF, 0x4D, 0xB9, 0x55, 0xCC, 0x2C, 0xA5, 0xF0, 0xA1, 0xEA, 0xD0, 0x01, 0x28, 0xDE, 0xF2, 0xD8, 0x25, 0xC9, 0xC6, 0x2B, 0x0F, 0x41, 0xBE, 0x2A, 0x85, 0x56, 0xC2, 0xC5, 0x54, 0x83, 0x8F, 0xF5, 0x1A, 0x51, 0xC5, 0x37, 0x2E, 0x86, 0xCA, 0x91, 0x8C, 0xFC, 0xE8, 0xD1, 0x37, 0xA7, 0x7B, 0xF6, 0x99, 0x71, 0xFD, 0x50, 0xC4, 0x01, 0x3A, 0xB0, 0xCB, 0xCB, 0xC6, 0xBC, 0x7C, 0x8E, 0xB3, 0x8D, 0xC8, 0x6C, 0x0A, 0x56, 0xF1, 0x9A, 0xD5, 0x2C, 0x6D, 0x93, 0x98, 0xC3, 0xC1, 0xB9 };

S2C_EDH_PubKey_Sig dh_exchange(Peer &peer, const C2S_EDH_PubKey &client_key) {
	static const Integer p_eph("0xc5d1fff6e1e0b5b5a4220a369a4f504d59c7482724053c0d4b05426328031633bc79249c1c58c91b32e6802f20a1e7626859da201e7faad8406c702796cbdf3208a6cccb77baa29bec763a9a1fb868d79182f00957e890d762806b443e7fd2f75ef2eed5f56e92e5939ec15533a642b2212504b62ba72ca8e6c7fe28bbc8f687");
	static const Integer g_eph("0x2");
	static const Integer q_eph("0x62e8fffb70f05adad211051b4d27a826ace3a41392029e06a582a13194018b19de3c924e0e2c648d997340179050f3b1342ced100f3fd56c20363813cb65ef9904536665bbdd514df63b1d4d0fdc346bc8c17804abf4486bb14035a21f3fe97baf79776afab74972c9cf60aa99d321591092825b15d396547363ff145de47b43");

	static const Integer p_sta("0xcd8fd4b7415dee60366c437dc8b43cfb01e35540cdd79b22f60b6c6ad4c77571efc441a88c33e8bacaa6bcca3e5099d58a8415b35217a5119b4eb3893f1472b9ed168230c3ca982f32202658f88959881c1bdd98423af79caca5d517544f09214e4ff3d2e6108fa21776749af68282771799575269507bc69b20b66eb74d075e57a5b96c13180262b2a96ea3c42e128bcc064f5b4e7a451f12f074bd2e64d433ab380494ed53d1c45db97cc4b3da288bf3533499a5f607b55175cc1d7ef917459e8f77658638d918e23753cf29429b846dcd410e541a855ebb4d04d065627b0025bb37a2a75733c65bf9d0a9e4aeabcb07eea223e6aa9c084b86e1c100c83af11bdba33ac34e80afaee202ff8511f4451b48e91490d773816eff332e8db21bbe3e8bf30d0b4408bbe32b5db2695b413e1f87101ebc547446f01ec77105de81db454ad676e3401add8471a432da342518e0497df6db7e59cb09bf3accb685617695d07cff6a875de4bec17368509d02ade555a92dd4abdaf6c44300536cadddab");
	static const Integer g_sta("0x3");
	static const Integer q_sta("0x66c7ea5ba0aef7301b3621bee45a1e7d80f1aaa066ebcd917b05b6356a63bab8f7e220d44619f45d65535e651f284ceac5420ad9a90bd288cda759c49f8a395cf68b411861e54c179910132c7c44acc40e0deecc211d7bce5652ea8baa278490a727f9e9730847d10bbb3a4d7b41413b8bccaba934a83de34d905b375ba683af2bd2dcb6098c01315954b751e2170945e60327ada73d228f89783a5e97326a19d59c024a76a9e8e22edcbe6259ed1445f9a99a4cd2fb03daa8bae60ebf7c8ba2cf47bbb2c31c6c8c711ba9e794a14dc236e6a0872a0d42af5da6826832b13d8012dd9bd153ab99e32dfce854f25755e583f75111f3554e0425c370e080641d788dedd19d61a74057d771017fc288fa228da4748a486bb9c0b77f999746d90ddf1f45f98685a2045df195aed934ada09f0fc3880f5e2a3a23780f63b882ef40eda2a56b3b71a00d6ec238d2196d1a128c7024befb6dbf2ce584df9d665b42b0bb4ae83e7fb543aef25f60b9b4284e8156f2aad496ea55ed7b62218029b656eed5");

	static const SecByteBlock dh_sta_priv_key(serv_dh_static_priv, sizeof(serv_dh_static_priv));
	static const SecByteBlock peer_dh_sta_pub_key(client_dh_static_pub, sizeof(client_dh_static_pub));

	AutoSeededRandomPool rnd;

	// DSA Init
	CryptoPP::DSA::PrivateKey dsa_priv_key;
	LoadPrivateKey("dsa-private.key", dsa_priv_key);
	
	if (!dsa_priv_key.Validate(rnd, 3)) {
		printf("Couldn't validate DSA privkey\n");
	}

	// DH Init
	DH dh_eph, dh_sta;
	dh_eph.AccessGroupParameters().Initialize(p_eph, q_eph, g_eph);
	dh_sta.AccessGroupParameters().Initialize(p_sta, q_sta, g_sta);

	if(!dh_eph.GetGroupParameters().ValidateGroup(rnd, 3)) {
		printf("Failed to validate Ephemeral prime and generator\n");
		throw runtime_error("Failed to validate prime and generator");
	}
	
	if(!dh_sta.GetGroupParameters().ValidateGroup(rnd, 3)) {
		printf("Failed to validate Static prime and generator\n");
		throw runtime_error("Failed to validate prime and generator");
	}
	
	Integer v = ModularExponentiation(g_eph, q_eph, p_eph);
	if(v != Integer::One()) {
		printf("Failed to verify order of the Ephemeral subgroup\n");
		throw runtime_error("Failed to verify order of the subgroup");
	}
	
	v = ModularExponentiation(g_sta, q_sta, p_sta);
	if(v != Integer::One()) {
		printf("Failed to verify order of the Static subgroup\n");
		throw runtime_error("Failed to verify order of the subgroup");
	}

	// Unified Diffie-Hellman with different domain parameters for static and ephemeral keys
	DH2 dh(dh_sta, dh_eph);
	SecByteBlock dh_eph_priv_key(dh.EphemeralPrivateKeyLength());
	SecByteBlock dh_eph_pub_key(dh.EphemeralPublicKeyLength());
	dh.GenerateEphemeralKeyPair(rnd, dh_eph_priv_key, dh_eph_pub_key);

	SecByteBlock peer_dh_eph_pub_key(client_key.pub_key, sizeof(client_key.pub_key));
	
	puts("Pubkey:");
	printPacket(dh_eph_pub_key.BytePtr(), dh_eph_pub_key.SizeInBytes());

	SecByteBlock shared(dh.AgreedValueLength());
	if(!dh.Agree(shared, dh_sta_priv_key, dh_eph_priv_key, peer_dh_sta_pub_key, peer_dh_eph_pub_key)) {
		printf("Failed to reach shared secret\n");
		throw runtime_error("Failed to reach shared secret");
	}
	puts("Shared secret:");
	printPacket(shared.BytePtr(), shared.SizeInBytes());

	CryptoPP::SHA512 hash;
	CryptoPP::byte digest[CryptoPP::SHA512::DIGESTSIZE];
	hash.CalculateDigest(digest, shared.BytePtr(), shared.SizeInBytes());
	peer.set_salsa20_creds(digest);

	// Create packet
	S2C_EDH_PubKey_Sig ret = { 0 };

	ret.pid = htons(2);
	ret.len = htons(128);
	std::copy(dh_eph_pub_key.begin(), dh_eph_pub_key.end(), ret.pub_key);
	// Sign the DH pubkey with the DSA privkey
	// Make sure the client has the corresponding DSA pubkey loaded in
	ret.len_sig = htons(56);
	CryptoPP::DSA::Signer signer(dsa_priv_key);
    CryptoPP::SecByteBlock signatureBlock(signer.MaxSignatureLength());
	size_t signatureSize = signer.SignMessage(rnd, ret.pub_key, sizeof(ret.pub_key), signatureBlock);
	std::copy(signatureBlock.begin(), signatureBlock.begin() + signatureSize, ret.sig);

	return ret;
}

int main(void) 
{
    WSADATA wsaData;
    int iResult;

    SOCKET ListenSocket = INVALID_SOCKET;
    SOCKET ClientSocket = INVALID_SOCKET;

    struct addrinfo *result = NULL;
    struct addrinfo hints;

    int iSendResult;
    char recvbuf[DEFAULT_BUFLEN];
    int recvbuflen = DEFAULT_BUFLEN;
    
    // Initialize Winsock
    iResult = WSAStartup(MAKEWORD(2,2), &wsaData);
    if (iResult != 0) {
        printf("WSAStartup failed with error: %d\n", iResult);
        return 1;
    }

    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;

    // Resolve the server address and port
    iResult = getaddrinfo(NULL, DEFAULT_PORT, &hints, &result);
    if ( iResult != 0 ) {
        printf("getaddrinfo failed with error: %d\n", iResult);
        WSACleanup();
        return 1;
    }

    // Create a SOCKET for the server to listen for client connections.
    ListenSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (ListenSocket == INVALID_SOCKET) {
        printf("socket failed with error: %ld\n", WSAGetLastError());
        freeaddrinfo(result);
        WSACleanup();
        return 1;
    }

    // Setup the TCP listening socket
    iResult = ::bind(ListenSocket, result->ai_addr, (int)result->ai_addrlen);
    if (iResult == SOCKET_ERROR) {
        printf("bind failed with error: %d\n", WSAGetLastError());
        freeaddrinfo(result);
        closesocket(ListenSocket);
        WSACleanup();
        return 1;
    }

    freeaddrinfo(result);

    iResult = listen(ListenSocket, SOMAXCONN);
    if (iResult == SOCKET_ERROR) {
        printf("listen failed with error: %d\n", WSAGetLastError());
        closesocket(ListenSocket);
        WSACleanup();
        return 1;
    }

    // Accept a client socket
    ClientSocket = accept(ListenSocket, NULL, NULL);
    if (ClientSocket == INVALID_SOCKET) {
        printf("accept failed with error: %d\n", WSAGetLastError());
        closesocket(ListenSocket);
        WSACleanup();
        return 1;
    }
	
	Peer peer(ClientSocket);

    // No longer need server socket
    closesocket(ListenSocket);

    // Receive until the peer shuts down the connection
    do {
        iResult = recv(peer.socket, recvbuf, recvbuflen, 0);
        if (iResult > 0) {
			printf("Bytes received: %d\n", iResult);

			if (peer.status == Peer::Status::None) {
				C2S_EDH_PubKey *in = reinterpret_cast<C2S_EDH_PubKey *>(recvbuf);
				//printPacket((const uint8_t*)in, iResult);
				auto ret = dh_exchange(peer, *in);
				iSendResult = send(peer.socket, (const char*)&ret, sizeof(ret), 0 );
				if (iSendResult == SOCKET_ERROR) {
					printf("send failed with error: %d\n", WSAGetLastError());
					closesocket(peer.socket);
					WSACleanup();
					return 1;
				}
				printf("Bytes sent: %d\n", iSendResult);
			} else if (peer.status == Peer::Status::CryptoSetup) {
				std::vector<uint8_t> decrypted_packet = peer.decrypt_packet((const unsigned char*)recvbuf, iResult);
				printPacket(&decrypted_packet[0], iResult);
			}

            if (iSendResult == SOCKET_ERROR) {
                printf("send failed with error: %d\n", WSAGetLastError());
                closesocket(peer.socket);
                WSACleanup();
                return 1;
            }
            
        }
        else if (iResult == 0)
            printf("Connection closing...\n");
        else  {
            printf("recv failed with error: %d\n", WSAGetLastError());
            closesocket(peer.socket);
            WSACleanup();
            return 1;
        }
		printf("iResult = %u\n", iResult);
    } while (iResult > 0);

    // shutdown the connection since we're done
    iResult = shutdown(ClientSocket, SD_SEND);
    if (iResult == SOCKET_ERROR) {
        printf("shutdown failed with error: %d\n", WSAGetLastError());
        closesocket(ClientSocket);
        WSACleanup();
        return 1;
    }

    // cleanup
    closesocket(ClientSocket);
    WSACleanup();

    return 0;
}