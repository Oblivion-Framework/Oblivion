#include <windows.h>
#include <stdio.h>

#define PIPE_NAME "\\\\.\\pipe\\MyNamedPipe"

int main() {
    HANDLE hPipe;
    char buffer[1024];
    DWORD bytesRead, bytesWritten;

    hPipe = CreateFile(PIPE_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);

    if (hPipe == INVALID_HANDLE_VALUE)
	{
        printf("CreateFile failed\n");
        return 1;
    }

	printf("Connected to the server!\n");
	
	while(true)
	{
		if(!ReadFile(hPipe, buffer, 1024, &bytesRead, NULL))
		{
			printf("ReadFile failed\n");
            break;
		}
		
		if(bytesRead == 0)
		{
            printf("Client disconnected or sent empty data.");
            break;
        }
		
		buffer[bytesRead] = '\0';
        std::cout << "Received: " << buffer << std::endl;
		
		char* response = "Command output: " + (buffer);
		
        if(!WriteFile(hPipe, response, sizeof(response), &bytesWritten, NULL))
		{
            std::cerr << "WriteFile failed: " << GetLastError() << std::endl;
            break;
        }
	}


    CloseHandle(hPipe);
    return 0;
}
