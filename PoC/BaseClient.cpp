#include <iostream>
#include <random>
#include <string>
#include <zmq.hpp>
#include <sodium.h>

// install zeromq and cppzmq package
// -lzmq flag may be needed and -lsodium
// g++ client.cpp -lzmq -lsodium -o client

int modularExp(int base, int exp, int mod)
{
	int result = 1;
	while(exp > 0)
	{
		if(exp & 1)
		{
			result = (result * base) % mod;
			result = (result * result) % mod;
		}
		base = (base * base) % mod;
		exp >>= 2;
	}
	return result;
}

int DiffieHellman(std::mt19937& Generator, std::uniform_int_distribution<int>& Distribution, zmq::socket_t* socket)
{
	std::string num1;
    std::string num2;

	int PrivKey = Distribution(Generator);

	zmq::message_t keys;

	if(!socket->recv(keys, zmq::recv_flags::none))
	{
		return -1;
	}

	std::string messageCast(static_cast<char*>(keys.data()), keys.size());
	std::istringstream iss(messageCast);

	std::getline(iss, num1, '+');
	std::getline(iss, num2, '+');

	int PubKey = modularExp(stol(num1), PrivKey, stol(num2));
	
	keys = (zmq::message_t)(std::to_string(PubKey));

	if(!socket->send(keys, zmq::send_flags::none))
	{
		return 1;
	}

	if(!socket->recv(keys, zmq::recv_flags::none))
	{
		return 1;
	}
	int Shared = stol(keys.to_string());
	
	return modularExp(Shared, PrivKey, stol(num2));
}

std::string Encrypt(std::string message, unsigned char* key, unsigned char* nonce)
{
	std::vector<unsigned char>ciphertext(message.size() + crypto_aead_chacha20poly1305_ABYTES);
	unsigned long long ciphertext_len;
	
	std::vector<unsigned char> msg(message.begin(), message.end());
	
	int status = crypto_aead_xchacha20poly1305_ietf_encrypt(ciphertext.data(), &ciphertext_len, msg.data(), msg.size(), nullptr, 0, nullptr, nonce, key);
	if(status)
	{
		std::cout << "[-] Error encrypting string, terminating now!\n";
		exit(-1);
	}
	return std::string(ciphertext.begin(), ciphertext.end());
}

std::string Decrypt(std::string ciphertext, unsigned char* key, unsigned char* nonce)
{
	std::vector<unsigned char>plaintext(ciphertext.size() - crypto_aead_chacha20poly1305_ABYTES);
	// crypto_aead_chacha20poly1305_ABYTES is 16
	unsigned long long message_len;
	std::vector<unsigned char>cphrtxt(ciphertext.begin(), ciphertext.end());

	int status = crypto_aead_xchacha20poly1305_ietf_decrypt(plaintext.data(), &message_len, nullptr, cphrtxt.data(), cphrtxt.size(), nullptr, 0, nonce, key);
	if(status)
	{
		std::cout << "Error decrypting string, terminating now!\n";
		exit(-1);
	}
	return std::string(plaintext.begin(), plaintext.end());
}

void HandleConnection(zmq::socket_t* socket, std::vector<unsigned char>& key, std::vector<unsigned char>& nonce)
{
	zmq::message_t message;
	while(true)
	{
		if(!socket->recv(message, zmq::recv_flags::none))
		{
			std::cout << "[-] Send failed!\n";
			socket->close();
			break;
		}

		std::string response = Decrypt(message.to_string(), key.data(), nonce.data());
		if(response == "terminate")
		{
			socket->close();
			break;

		}

		zmq::message_t resp = (zmq::message_t)(Encrypt(response, key.data(), nonce.data()));
		if(!socket->send(resp, zmq::send_flags::none))
		{
			std::cout << "[-] Receive failed!\n";
			socket->close();
			break;
		}
	}
}

int main()
{
	zmq::context_t ctx(1);
	zmq::socket_t socket(ctx, zmq::socket_type::pair);

	std::random_device Device;
	std::mt19937 Generator(Device());
	std::uniform_int_distribution<int> Distribution(0, 100);

	socket.connect("tcp://127.0.0.1:6666");
	zmq::message_t message;
	if(!socket.send(zmq::str_buffer("zerodium"), zmq::send_flags::none))
	{
		std::cout << "[-] Failed to send 'zerodium', terminating!\n";
		socket.close();
		ctx.close();
		return 1;
	}

	int Secret = DiffieHellman(Generator, Distribution, &socket);

	if(Secret == -1)
	{
		std::cout << "[-] Diffie hellman failed!\n";
		socket.close();
		ctx.close();
		return 1;
	}
	std::vector<unsigned char>key(32, static_cast<unsigned char>(Secret));
	std::vector<unsigned char>nonce(24, static_cast<unsigned char>(Secret));

	HandleConnection( &socket,  key, nonce);
	ctx.close();
}
