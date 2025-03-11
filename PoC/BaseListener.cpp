#include <cstring>
#include <iostream>
#include <random>
#include <sodium.h>
#include <string>
#include <vector>
#include <zmq.hpp>
#include <unordered_map>
#include <tuple>
#include <memory>
#include <variant>


// g++ FixListen.cpp -lzmq -lsodium -o listener

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

void ToLowerCase(std::string& str)
{
	for(char &c : str)
	{
		if(c >= 'A' && c <= 'Z')
		{
			c += 32;
		}
	}
}

std::vector<std::string> tokenize(std::string input, const char* delimiter)
{
	std::vector<std::string> output;
	int pos = 0;
	while(pos != std::string::npos)
	{
		pos = input.find(delimiter);
		output.emplace_back(input.substr(0, pos));
		input.erase(0, pos+strlen(delimiter));
	}
	return output;
}


int DiffieHellman(std::uniform_int_distribution<int>& Distribution, std::mt19937& Generator, std::shared_ptr<zmq::socket_t> socket)
{
	zmq::message_t keys;

	int Public_P = Distribution(Generator);
	int Public_G = Distribution(Generator);
	int Private_val = Distribution(Generator);

	keys = (zmq::message_t)(std::to_string(Public_G) + "+" + std::to_string(Public_P));
	socket->send(keys, zmq::send_flags::none);
	int Public_key = modularExp(Public_G, Private_val, Public_P);

	if(!socket->recv(keys, zmq::recv_flags::none))
	{
		return -1;
	}

	int Shared = stol(keys.to_string());
	keys = (zmq::message_t)(std::to_string(Public_key));

	socket->send(keys, zmq::send_flags::none);
	
	return modularExp(Shared, Private_val, Public_P);
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

void HandleConnection(std::shared_ptr<zmq::socket_t> socket, std::vector<unsigned char>& key, std::vector<unsigned char>& nonce)
{
	zmq::message_t message;
	std::string buffer;

	while(true)
	{
		std::cout << "Enter a message: ";

		std::getline (std::cin,buffer);
		if(buffer == "leave")
		{
			break;
		}
		message = (zmq::message_t)(Encrypt(buffer, key.data(), nonce.data()));

		if(!socket->send(message, zmq::send_flags::none))
		{
			std::cout << "[-] Send failed!\n";
			socket->close();
			break;
		}
		
		if(!socket->recv(message, zmq::recv_flags::none))
		{
			std::cout << "[-] Receive failed!\n";
			socket->close();
			break;
		}
		std::cout << "Received: " << Decrypt(message.to_string(), key.data(), nonce.data()) << std::endl;
	}
}

int main()
{
	int counter = 0;

	std::random_device Device;
	std::mt19937 Generator(Device());
	std::uniform_int_distribution<int> Distribution(0, 100);

	zmq::context_t ctx(1);

	std::string inp;
	std::vector<std::string> command;
	std::unordered_map<int, std::tuple<std::shared_ptr<zmq::socket_t>, std::vector<unsigned char>, std::vector<unsigned char>>> lists;

	std::unordered_map<std::string, std::variant<void(*)()>> Fns;

	while(true)
	{
		std::cout << "$ ";
		std::getline(std::cin, inp);
		command = tokenize(inp, " ");
		for(std::string i : command)
		{
			ToLowerCase(i);
		}
		
		if(command[0] == "exit")
		{
			exit(0);
		}
		else if(command[0] == "bind")
		{
			std::shared_ptr<zmq::socket_t> socket = std::make_shared<zmq::socket_t>(ctx, zmq::socket_type::pair);
			socket->bind("tcp://127.0.0.1:" + command[1]);
			std::cout << "[!] Started listener on port " << command[1] << std::endl;
			zmq::message_t message;

			if(!socket->recv(message, zmq::recv_flags::none))
			{
				std::cout << "[-] Failed to recieve 'zerodium', terminating!\n";
				socket->close();
				ctx.close();
				continue;
			}
			if(message.to_string() != "zerodium")
			{
				std::cout << "[-] Failed to recieve 'zerodium', received " << message.to_string() <<  " terminating!\n";
				socket->close();
				ctx.close();
				continue;
			}

			int Secret = DiffieHellman(Distribution, Generator, socket);

			if(Secret == -1)
			{
				std::cout << "[-] Diffie hellman failed!\n";
				socket->close();
				ctx.close();
				continue;
			}

			std::vector<unsigned char>key(32, static_cast<unsigned char>(Secret));
			std::vector<unsigned char>nonce(24, static_cast<unsigned char>(Secret));

			counter += 1;

			lists[counter] = std::make_tuple(socket, key, nonce);

			HandleConnection(socket, key, nonce);
		}
		else if(command[0] == "list")
		{
			if(!lists.size())
			{
				std::cout << "No connections currently made!" << std::endl;
			}

			std::cout << "Connections:\n--------------------------------n";

			for(int i = 0; i < lists.size(); i++)
			{
				std::cout << i << "\t|\t" << std::get<0>(lists[i]) << std::endl;
			}
		}
		else if(command[0] == "help")
		{
			std::cout << "\n1. exit\n2. clear\n3. bind\n4. terminate\n5. help\n6. interact\n7. list\n\n";
		}
		else if(command[0] == "terminate")
		{
			int idx = std::stoi(command[1]);
			std::get<0>(lists[idx])->send((zmq::message_t)Encrypt(std::string("terminate"), std::get<1>(lists[idx]).data(), std::get<2>(lists[idx]).data()), zmq::send_flags::none);
			std::get<0>(lists[idx])->close();
			lists.erase(idx);
		}
		else if(command[0] == "clear")
		{
			system("clear");
		}
		else if(command[0] == "interact")
		{
			int idx = std::stoi(command[1]);
			HandleConnection(std::get<0>(lists[idx]), std::get<1>(lists[idx]), std::get<2>(lists[idx]));
		}
		else {
			std::cout << "Try again!!\n";
		}
	}
}
