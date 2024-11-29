##
##
## Project Name
##
##
Project := Oblivion
##
##Compiler
##
CC_X64	:= x86_64-w64-mingw32-g++

##
## x64
##
EXE-X64	:= $(Project).x64.exe

##
##Build src and executable
##
x64:
	@ echo "[+] compile x64 executable"
	@ $(CC_X64) -o ..\obj\Persistence.x64.o -c ..\payloads\yeti\persistence.cpp
	@ echo "[+] compile x64 executable"
	@ $(CC_X64) -o $(EXE-X64) ..\obj\\*.x64.o

	