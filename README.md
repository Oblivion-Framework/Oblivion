### Improved File Tree for C2 Framework: **OBLIVION FRAMEWORK**

```
OBLIVION_FRAMEWORK/
│
├── Build/
│   ├── Makefile               # The Makefile that compiles the project (includes build rules, dependencies, etc.)
│   └── CMakeLists.txt         # CMake configuration file (alternative to Makefile, could be useful for cross-platform builds)
│
├── Config/                    # Configuration files for setting up server/client settings, persistence, logging, etc.
│   ├── server_config.json     # Configuration for server settings (e.g., IP, port, protocols)
│   ├── client_config.json     # Configuration for client-side settings (e.g., polling intervals, server address)
│   └── persistence_config.json # Settings for persistence mechanisms (e.g., registry keys, startup entries)
│
├── Docs/                      # Documentation for users and developers
│   ├── README.md              # Main README file describing the framework, setup, and usage
│   ├── INSTALL.md             # Instructions on setting up the framework, dependencies, and installation
│   └── API.md                 # Documentation for the API of the framework (client-server interactions, modules)
│
├── Handlers/                  # Handlers for different tasks like system commands, data parsing, etc.
│   ├── system_handler.cpp     # System commands handling (reboot, shutdown, process management)
│   └── data_handler.cpp       # Handling data packets, communication protocols, encryption/decryption
│
├── Libs/                       # External libraries or custom helper classes
│   ├── cryptography.cpp       # Custom encryption/decryption logic (for communication security)
│   ├── network_utils.cpp      # Helper functions for managing networking (socket setup, send/receive)
│   └── utils.cpp              # General utility functions (e.g., file handling, error handling)
│
├── Listeners/                 # Listener components that establish connection points for the C2 communication
│   ├── client.cpp             # Client side of the communication (listens for commands, sends data to server)
│   ├── server.cpp             # Server side of the communication (receives requests, sends commands to clients)
│   ├── piped/                 # Named Pipe listeners (IPC-based communication)
│   │   ├── client_named_pipe.cpp  # Client side using named pipes for communication
│   │   └── server_named_pipe.cpp  # Server side using named pipes for communication
│   └── socket/                # Sockets as an alternative for named pipes (for TCP/UDP-based communication)
│       ├── client_socket.cpp  # Client-side TCP/UDP socket communication
│       └── server_socket.cpp  # Server-side TCP/UDP socket communication
│
├── Logs/                      # Log files for debugging and monitoring client/server activities
│   ├── client_logs.txt        # Logs for client-side operations (e.g., keylogger output, persistence actions)
│   ├── server_logs.txt        # Logs for server-side actions (e.g., received commands, data, errors)
│   └── error_logs.txt         # General error logs to track failures in the system
│
├── Modules/                   # Core modules or payloads of the framework
│   ├── clipboard.cpp          # Clipboard monitoring (captures copied content and sends it to the server)
│   ├── keylogger.cpp          # Keylogging module (captures keystrokes and sends them to the server)
│   ├── persistence.cpp        # Persistence module (ensures that the client survives reboots and re-executions)
│   ├── recon.cpp              # Reconnaissance module (collects system info like OS, network settings, processes)
│   ├── file_manager.cpp       # Manages file-related operations (copying, deleting, modifying files remotely)
│   └── process_manager.cpp    # Manages processes (creates, terminates, or suspends processes remotely)
│
├── PoC/                       # Proof-of-Concept files (demonstration of vulnerabilities, techniques, or exploits)
│   ├── privilege_escalation_poc.cpp  # PoC demonstrating privilege escalation techniques
│   ├── bypass_antivirus_poc.cpp       # PoC demonstrating antivirus evasion methods
│   └── firewall_bypass_poc.cpp        # PoC demonstrating firewall bypass methods
│
├── Scripts/                   # Utility scripts for tasks like building, deploying, cleaning up, etc.
│   ├── build.sh               # Shell script to automate the build process
│   ├── deploy.sh              # Deployment script for setting up clients on target systems
│   └── cleanup.sh             # Script for cleaning up traces of the framework after use
│
├── Src/                        # Source files for the C2 framework's core functionality
│   ├── main.cpp               # Main entry point for the client or server (handles initialization, setup, and execution)
│   ├── c2_core.cpp            # Core framework functionalities (e.g., communication setup, module execution)
│   └── security.cpp           # Security-related functionalities (e.g., encryption, secure communications)
│
└── Tests/                     # Unit tests or integration tests for the framework
    ├── unit_tests.cpp         # Tests for individual modules (e.g., keylogger, persistence)
    ├── integration_tests.cpp  # Tests for end-to-end functionality (server-client interactions, file transfers)
    └── test_utils.cpp         # Utility functions for testing, mocks, and setup/teardown helpers
```
### Explanation of Each Section:

1. **Build/**:
    
    - **Makefile**: The build system file to compile the entire framework.
    - **CMakeLists.txt**: An alternative to the `Makefile` for using **CMake**, allowing more flexibility, especially for cross-platform development (e.g., Linux, macOS, Windows).
2. **Config/**:
    
    - Configuration files (in `.json` or `.xml` format) allow the user to specify settings for the server and client, persistence, and other parameters without hardcoding them into the code. For example:
        - **server_config.json** could contain settings like IP, port, and security protocols.
        - **persistence_config.json** could define which persistence techniques to use.
    - This makes the framework easily customizable and scalable.
3. **Docs/**:
    
    - Essential documentation like **README.md** for general users, **INSTALL.md** for installation steps, and **API.md** for developers working with the C2 framework.
    - Well-organized documentation is crucial for users to set up, use, and extend the framework.
4. **Handlers/**:
    
    - These files are responsible for handling different tasks like processing system commands, parsing incoming data, or managing the communication channels.
    - **system_handler.cpp** could handle system commands like shutting down a target or launching processes.
    - **data_handler.cpp** could handle encryption and parsing of data packets.
5. **Libs/**:
    
    - Includes helper libraries or custom functions. For instance, **cryptography.cpp** may provide methods for encrypting/decrypting communication, and **network_utils.cpp** could handle socket setup and data transmission.
    - **utils.cpp** might include general-purpose functions like logging, error handling, or file management.
6. **Listeners/**:
    
    - The communication handlers for the server and client. This is where named pipe or socket-based connections are set up:
        - **client.cpp** and **server.cpp** are the main entry points for client-server communication.
        - **piped/**: Contains code for IPC using Named Pipes (`client_named_pipe.cpp` for the client and `server_named_pipe.cpp` for the server).
        - **socket/**: Contains code for socket-based communication for more traditional network-based C2 server-client setups.
7. **Logs/**:
    
    - Logs should be created for various components, such as the **client_logs.txt** for activity related to the keylogger, clipboard, etc., and **server_logs.txt** for monitoring server operations (e.g., commands received, errors).
    - **error_logs.txt** helps in tracking any issues that arise during runtime.
8. **Modules/**:
    
    - The core payloads and functionalities of the C2 framework, like **keylogger.cpp**, **clipboard.cpp**, **persistence.cpp**, and **recon.cpp**.
    - These modules represent the actual malicious actions or tests that can be run once the client is installed on a target machine.
9. **PoC/**:
    
    - **Proof-of-Concept** files demonstrate how the framework can be used for particular offensive actions like **privilege escalation** or **bypassing antivirus software**.
    - These files are useful for showcasing exploits or validating techniques.
10. **Scripts/**:
    
    - Shell or batch scripts to automate tasks like building the framework (`build.sh`), deploying the payload (`deploy.sh`), or cleaning up after testing or usage (`cleanup.sh`).
11. **Src/**:
    
    - **main.cpp** is the entry point for the client or server, initializing the core framework.
    - **c2_core.cpp** handles core functionality, including managing communication and execution of modules.
    - **security.cpp** contains the security measures like encryption to ensure the framework's communication is stealthy and secure.
12. **Tests/**:
    
    - Unit and integration tests help ensure the stability and security of the framework. **unit_tests.cpp** tests individual components like keylogging, persistence, etc., while **integration_tests.cpp** ensures that all components work together as expected.
    - **test_utils.cpp** provides utility functions to make testing easier.

---

### Additional Thoughts:
- **Encryption**: Implement a robust **encryption system** for communication between client and server to prevent detection by IDS/IPS systems or packet sniffers.

![diagram](https://github.com/Oblivion-Framework/Oblivion/blob/main/image.png)

---

kitty: backend communication
	listeners [client and server comms]
		- Implement and test different communication protocols (sockets, named pipes).

avale + syu: client side logic and interaction
	 modules [keylogger, clipboard, etc]
	 handlers [data handlers, system handlers, etc]
	 logs [client/server/error logs]
	 tests [unit tests, etc]
		 - Focus on implementing client-side functionality, such as keylogging, clipboard monitoring, and process management.
		- Develop handlers for processing incoming commands and interacting with system functions.
		- Monitor and log client-side actions and errors for debugging and analysis.
		- Write unit tests for client-side modules, ensuring the reliability and accuracy of core functionalities.

syu: server side logic, security, deployment
	config [server.json, persistence.json]
	modules [recon, file, process managing]
	scripts [py scripts general use]
	docs[readmes, api docs]
		- Develop deployment scripts for setting up clients on target systems and configuring persistence mechanisms.
		- Update documentation to ensure clear setup instructions, API references, and module functionalities.

avale + kitty: comm & module integration:
**Collaborative Areas:**

- Integrating communication mechanisms (e.g., between listeners and modules).
- Combining backend server-client functionality with specific modules (e.g., keylogger, persistence).
- Testing communication between client-server modules.


syu + kitty + avale: security core funcs / deployment, test & docs:
**Collaborative Areas:**

- Integrating security measures into the core framework (e.g., encryption, secure communication channels).
- Ensuring modules like recon and process management work securely.
- Setting up server-client security mechanisms.
- Building and deploying clients to target systems.
- Writing unit tests and integration tests for modules.
- Updating documentation based on the integration of new features and functionalities.


ALL 3:
- **Initial Setup and Architecture Design:**
    
    - **Collaborative Areas:**
        - Design the framework architecture, discussing how components like the listener, modules, and server-client communication should interact.
        - Decide on the configuration files, dependencies, and environment variables required for the framework.
    - **Responsibilities:**
        - All team members contribute to defining the system architecture, ensuring that each part fits together smoothly and securely.
- **Integration and Testing:**
    
    - **Collaborative Areas:**
        - Integration of individual modules into the main framework. For example, combining the persistence mechanism with the recon module.
        - Testing and debugging integration points where multiple components interact (e.g., server-client communication).
    - **Responsibilities:**
        - All members will work together to run integration tests and identify potential issues. Ensure that all the features (modules, handlers, listeners) work as expected in the system.
- **Deployment & Maintenance:**
    
    - **Collaborative Areas:**
        - Finalize deployment processes and setup procedures.
        - Ensure the system is ready for real-world use and handle any bugs or issues during deployment.
    - **Responsibilities:**
        - The team will collaborate to finalize deployment scripts, update any necessary configurations, and ensure that everything runs smoothly in both client and server environments.
