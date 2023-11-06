#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <iostream>
#include <DbgHelp.h>
#include <fstream>

DWORD processId = -1;
std::string output = "";

HANDLE hProcess;
HANDLE hThreadSnap;
HMODULE hNtdll;

DWORD64 ntdllBaseAddress;
MODULEINFO ntdllModuleInfo;

DWORD64 getRIPAddress(DWORD tid) {
    HANDLE hThread = OpenThread(THREAD_GET_CONTEXT, FALSE, tid);
    if (hThread) {
        CONTEXT context;
        context.ContextFlags = CONTEXT_FULL;

        if (GetThreadContext(hThread, &context)) {
            //std::cout << "RIP: 0x" << std::hex << context.Rip << std::endl;
            return context.Rip;
        }

        CloseHandle(hThread);
    }

    return 0;
}

DWORD64 getReturnAddress(DWORD tid) {
    HANDLE hThread = OpenThread(THREAD_GET_CONTEXT, FALSE, tid);
    if (hThread) {
        CONTEXT context;
        context.ContextFlags = CONTEXT_FULL;

        if (GetThreadContext(hThread, &context)) {
            DWORD_PTR rspValue;
            if (ReadProcessMemory(hProcess, reinterpret_cast<LPVOID>(context.Rsp), &rspValue, sizeof(rspValue), NULL)) {
                //std::cout << "RSP: 0x" << std::hex << context.Rsp << std::endl;
                //std::cout << "Value on the stack: 0x" << std::hex << rspValue << std::endl;
                return rspValue;
            }
        }

        CloseHandle(hThread);
    }

    return 0;
}

DWORD64 getFunctionAddress(DWORD64 address) {
    SymSetOptions(SYMOPT_DEFERRED_LOADS | SYMOPT_LOAD_LINES);
    if (SymInitialize(hProcess, nullptr, TRUE)) {
        IMAGEHLP_MODULE64 moduleInfo;
        moduleInfo.SizeOfStruct = sizeof(IMAGEHLP_MODULE64);
        if (SymGetModuleInfo64(hProcess, address, &moduleInfo)) {
            DWORD64 displacement;
            CHAR symbolBuffer[sizeof(IMAGEHLP_SYMBOL64) + MAX_PATH];
            PIMAGEHLP_SYMBOL64 symbol = (PIMAGEHLP_SYMBOL64)symbolBuffer;
            symbol->SizeOfStruct = sizeof(IMAGEHLP_SYMBOL64);
            symbol->MaxNameLength = MAX_PATH;
            if (SymGetSymFromAddr64(hProcess, address, &displacement, symbol)) {
                //std::cout << "Direccion: 0x" << std::hex << address - displacement << std::endl;
                SymCleanup(hProcess);
                return address - displacement;
            }
        }
        SymCleanup(hProcess);
    }

    return 0x0;
}

DWORD checkForPrevCallInst(DWORD64 address) {
    DWORD64 data;
    if (ReadProcessMemory(hProcess, reinterpret_cast<LPVOID>(address - 0x7), &data, sizeof(data), NULL)) {
        //std::cout << "Data at address 0x" << std::hex << address << ": 0x" << std::hex << data << std::endl;
        //std::cout << "test 0x" << std::hex << (data & 0x15FF48) << std::endl;
        DWORD64 combinations[] = {0xE8, 0x15FF, 0xDFF, 0xDFF41};
        if(data & 0xE80000) {
            return 0xE8;
        }

        if(data & 0x15FF48) {
            return 0x15FF48;
        }

        if(data & 0xFFD000000) {
            return 0xDFF;
        }

        if(data & 0xDFF410000) {
            return 0xDFF41;
        }
    }

    return 0;
}

bool checkForInvalidPrevCallInst(DWORD64 ripAddress, DWORD64 callAddress, DWORD callType) {
    DWORD64 data;
    if (ReadProcessMemory(hProcess, reinterpret_cast<LPVOID>(callAddress - 0x7), &data, sizeof(data), NULL)) {
        if(callType == 0xE8) {
            DWORD desp = (data >> 24) & 0xFFFFFFFF;
            DWORD64 offset = callAddress + desp;
            //std::cout << "Direct CALL to address: 0x" << std::hex << offset << std::endl;
            if(getFunctionAddress(ripAddress) != offset) {
                return true;
            }
        } else if(callType == 0x15FF48) {
            DWORD desp = (data >> 24) & 0xFFFFFFFF;
            DWORD64 offset_ptr = callAddress + desp;
            DWORD64 offset = 0x0;
            ReadProcessMemory(hProcess, (LPCVOID)offset_ptr, &offset, 8, NULL);
            //std::cout << "CALL to a memory pointer: 0x" << std::hex << offset << std::endl;
            if(getFunctionAddress(ripAddress) != offset) {
                return true;
            }
        } else if(callType == 0xDFF) {
            //std::cout << "CALL through a normal register x" << std::endl;
        } else if(callType == 0xDFF41) {
            //std::cout << "CALL through a R register x" << std::endl;
        }
    }
    return false;
}

bool isOutOfUserland(DWORD64 address) {
    LPVOID addressToCheck = (LPVOID)address;

    HMODULE hModuleList[1024];
    DWORD cbNeeded;
    if (EnumProcessModules(hProcess, hModuleList, sizeof(hModuleList), &cbNeeded)) {
        HMODULE hModule = GetModuleHandle(NULL);
        if (hModule == NULL) {
            std::cerr << "The main module could not be obtained." << std::endl;
            CloseHandle(hProcess);
            return 1;
        }

        MODULEINFO mainModuleInfo;
        if (GetModuleInformation(hProcess, hModule, &mainModuleInfo, sizeof(mainModuleInfo)) &&
            (addressToCheck >= mainModuleInfo.lpBaseOfDll) &&
            (addressToCheck < (LPVOID)((uintptr_t)mainModuleInfo.lpBaseOfDll + mainModuleInfo.SizeOfImage))) {
            //std::cout << "La dirección pertenece al módulo principal (el .exe)." << std::endl;
            return false;
        } else {
            //std::cout << "La dirección NO pertenece al módulo principal (el .exe)." << std::endl;
            return true;
        }
    } else {
        std::cerr << "Error when listing the modules of the process." << std::endl;
    }

    //std::cout << "The address belongs to userland." << std::endl;
    return false;
}

bool isNtdllAddress(DWORD64 address) {
    MODULEENTRY32 moduleEntry;
    moduleEntry.dwSize = sizeof(MODULEENTRY32);
    HANDLE hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, processId);

    if (hModuleSnap == INVALID_HANDLE_VALUE) {
        std::cerr << "Error when creating a module snapshot." << std::endl;
        CloseHandle(hProcess);
        return 1;
    }

    std::string targetModuleName = "ntdll.dll";

    if (Module32First(hModuleSnap, &moduleEntry)) {
        do {
            if (targetModuleName == moduleEntry.szModule) {
                if (GetModuleInformation(hProcess, moduleEntry.hModule, &ntdllModuleInfo, sizeof(MODULEINFO))) {
                    ntdllBaseAddress = reinterpret_cast<uintptr_t>(moduleEntry.modBaseAddr);
                } else {
                    std::cerr << "Error getting information from the module." << std::endl;
                }

                break;
            }
        } while (Module32Next(hModuleSnap, &moduleEntry));
    }

    CloseHandle(hModuleSnap);

    DWORD addr_rva = address - ntdllBaseAddress;
    if(addr_rva > 0x0 && addr_rva < ntdllModuleInfo.SizeOfImage) {
        //std::cout << "RIP is at NTDLL. Checking Return address..." << std::endl;
        return true;
    } else {
        //std::cout << "RIP is not at NTDLL. Closing..." << std::endl;
        return false;
    }
}

void writeLog() {
    std::cout << "---------------------------------------------------------------------------" << std::endl;
    std::cout << "[!] The callstack is incorrect. Possible callstack spoofing in PID: " << processId << std::endl;

    if(output != "") {
        std::ofstream writeFile(output, std::ios::app);

        if (writeFile.is_open()) {
            writeFile << "---------------------------------------------------------------------------" << std::endl;
            writeFile << "[!] The callstack is incorrect. Possible callstack spoofing in PID: " << processId << std::endl;

            writeFile.close();
        }
    }
}

bool checkForCallstackSpoof() {
    THREADENTRY32 threadEntry;
    threadEntry.dwSize = sizeof(THREADENTRY32);
    //std::cout << "--------------------------------------------------------------------" << std::endl;
    // Enumerar los hilos del proceso de destino.
    if (Thread32First(hThreadSnap, &threadEntry)) {
        do {
            if (threadEntry.th32OwnerProcessID == processId) {
                //std::cout << "Thread ID: " << threadEntry.th32ThreadID << std::endl;
                DWORD64 ripAddress = getRIPAddress(threadEntry.th32ThreadID);
                DWORD64 retPrevInstAddress = getReturnAddress(threadEntry.th32ThreadID);

                if(retPrevInstAddress == 0x0) {
                    continue;
                }

                //Comprobamos si está ejecutando código de la NTDLL
                if(isNtdllAddress(ripAddress)) {
                    //Comprobamos si el return es a userland
                    if(isOutOfUserland(retPrevInstAddress)) {
                        //Comprobamos si la instrucción previa a la de return es una CALL
                        DWORD callType = checkForPrevCallInst(retPrevInstAddress);
                        if(callType != 0) {
                            //std::cout << "Call found. Checking the call address..." << std::endl;
                            //Comprobamos si el desplazamiento de la CALL lleva hasta la función que está ejecutando el hilo
                            if(checkForInvalidPrevCallInst(ripAddress, retPrevInstAddress, callType)) {
                                writeLog();
                            }
                        } else {
                            writeLog();
                        }
                    }
                }

                //std::cout << "--------------------------------------------------------------------" << std::endl;
                //std::cout << "[*] The callstack is correct on TID 0x" << std::hex << threadEntry.th32ThreadID << std::endl;
                //std::cout << "--------------------------------------------------------------------" << std::endl;
            }
        } while (Thread32Next(hThreadSnap, &threadEntry));
    }

    return false;
}

void start_allProcess() {
    DWORD processes[1024];
    DWORD bytesReturned;
    if (!EnumProcesses(processes, sizeof(processes), &bytesReturned)) {
        std::cerr << "Error when listing processes." << std::endl;
        return;
    }

    int numProcesses = bytesReturned / sizeof(DWORD);

    for (int i = 0; i < numProcesses; i++) {
        //std::cout << "PID: " << processes[i] << std::endl;
        processId = processes[i];

        hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
        if (hProcess == NULL) {
            continue;
        }

        hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, processId);
        if (hThreadSnap == INVALID_HANDLE_VALUE) {
            std::cerr << "Error creating snapshot: " << GetLastError() << std::endl;
            CloseHandle(hProcess);
            continue;
        }

        checkForCallstackSpoof();
    }
}

void start_singleProcess() {
    hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    if (hProcess == NULL) {
        return;
    }

    hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, processId);
    if (hThreadSnap == INVALID_HANDLE_VALUE) {
        std::cerr << "Error creating snapshot: " << GetLastError() << std::endl;
    }

    checkForCallstackSpoof();
}

int main(int argc, char* argv[]) {
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--pid") == 0) {
            if (i + 1 < argc) {
                processId = std::atoi(argv[i + 1]);
                i++;
            }
        } else if (strcmp(argv[i], "-o") == 0 || strcmp(argv[i], "--output") == 0) {
            if (i + 1 < argc) {
                output = argv[i + 1];
                i++;
            }
        } else {
            std::cerr << "Error: Argument not recognized: " << argv[i] << std::endl;
            return 1;
        }
    }

    if(processId != -1) {
        start_singleProcess();
    } else {
        start_allProcess();
    }

    CloseHandle(hThreadSnap);
    CloseHandle(hProcess);
    
    return 0;
}
