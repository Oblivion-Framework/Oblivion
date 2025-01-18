#include <iostream>
#include <random>
#include <sodium.h>
#include <zmq.hpp>
#include <sstream>

// g++ listener.cpp -lzmq -lsodium -o listener

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
	std::ostringstream oss;
	for(auto byte: ciphertext)
	{
		oss << std::hex << static_cast<int>(byte);
	}
	//return oss.str();
	
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


int main()
{
	zmq::context_t ctx(1);
	zmq::socket_t socket(ctx, zmq::socket_type::pair);
	socket.bind("tcp://127.0.0.1:4444");
	std::cout << "[!] Started listener\n";
	zmq::message_t message;
	if(!socket.recv(message, zmq::recv_flags::none))
	{
		std::cout << "[-] Failed to recieve 'zerodium', terminating!\n";
		socket.close();
		ctx.close();
		return 1;
	}
	std::random_device Device;
	std::mt19937 Generator(Device());
	std::uniform_int_distribution<int> Distribution(0, 100);
	int Public_P = Distribution(Generator);
	int Public_G = Distribution(Generator);
	int Private_val = Distribution(Generator);

	//message = (zmq::message_t)(reinterpret_cast<std::string>(Public_G) + "+" + reinterpret_cast<std::string>(Public_P));
	message = (zmq::message_t)(std::to_string(Public_G) + "+" + std::to_string(Public_P));
	socket.send(message, zmq::send_flags::none);

	int Public_key = modularExp(Public_G, Private_val, Public_P);
	socket.recv(message, zmq::recv_flags::none);
	int Shared = stol(message.to_string());
	
	message = (zmq::message_t)(std::to_string(Public_key));

	socket.send(message, zmq::send_flags::none);
	
	int Secret = modularExp(Shared, Private_val, Public_P);


	std::vector<unsigned char>key(32, static_cast<unsigned char>(Secret));
	std::vector<unsigned char>nonce(24, static_cast<unsigned char>(Secret));

	std::string buffer;

	while(true)
	{
		std::cout << "Enter a message: ";
		//std::cin >> buffer;
		std::getline (std::cin,buffer);
		message = (zmq::message_t)(Encrypt(buffer, key.data(), nonce.data()));
		socket.send(message, zmq::send_flags::none);
		
		socket.recv(message, zmq::recv_flags::none);
		std::cout << "Received: " << Decrypt(message.to_string(), key.data(), nonce.data()) << std::endl;
	}

}
