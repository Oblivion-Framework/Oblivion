#include <windows.h>
#include <iostream>
#include <string>

#define PIPE_NAME "\\\\.\\pipe\\MyNamedPipe"


int main() {
    HANDLE hPipe;
    char buffer[1024];
    DWORD bytesRead;
    DWORD bytesWritten;
	
    // Create a named pipe for communication
    hPipe = CreateNamedPipe(PIPE_NAME, PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT, PIPE_UNLIMITED_INSTANCES, 1024, 1024, 0, NULL);

    if (hPipe == INVALID_HANDLE_VALUE)
	{
        std::cerr << "CreateNamedPipe failed: " << GetLastError() << std::endl;
        return 1;
    }

    std::cout << "Waiting for client to connect..." << std::endl;

	if(!ConnectNamedPipe(hPipe, NULL))
	{
		std::cerr << "ConnectNamedPipe failed: " << GetLastError() << std::endl;
		return 1;
	}
	
	std::cout << "Client connected!" << std::endl;
	
	 while (true)
	{
        std::string message;
        std::cout << "Enter message for server: ";
        std::getline(std::cin, message);

        if (message == "exit")
		{
            break;
        }
		
		if(message == "")
		{
			std::cout << "Saved ya ass from haltin the blooody pipe mate >:(" << std::endl;
			continue;
		}

        if (!WriteFile(hPipe, message.c_str(), message.length(), &bytesWritten, NULL))
		{
            std::cerr << "WriteFile failed: " << GetLastError() << std::endl;
            break;
        }

        if (!ReadFile(hPipe, buffer, 1024, &bytesRead, NULL))
		{
            std::cerr << "ReadFile failed: " << GetLastError() << std::endl;
            break;
        }

        buffer[bytesRead] = '\0';
        std::cout << "Server says: " << buffer << std::endl;
    }

	DisconnectNamedPipe(hPipe);
	CloseHandle(hPipe);
	std::cout << "Client disconnected." << std::endl;
    return 0;
}
