#include <Windows.h>
#include <winnt.h>
#include <iostream>
#include <clocale>
#include "Structs.h"

PTEB RtlGetThreadEnvironmentBlock() {
#if _WIN64
	return (PTEB)__readgsqword(0x30);
#else
	return (PTEB)__readfsdword(0x16);
#endif
}

void printBanner() {
	const char* banner ="\n"
		"	  .oooooo.             oooo             .o8                                      \n"
		"	 d8P'  `Y8b            `888            \"888                                     \n"
		"	888           .ooooo.   888   .ooooo.   888oooo.   .ooooo.  oooo d8b ooo. .oo.  \n"
		"	888          d88' `88b  888  d88' `88b  d88' `88b d88' `88b `888\"\"8P `888P\"Y88b  \n"
		"	888          888ooo888  888  888ooo888  888   888 888   888  888      888   888  \n"
		"	 88b    ooo  888    .o  888  888    .o  888   888 888   888  888      888   888  \n"
		"	 `Y8bood8P'  `Y8bod8P' o888o `Y8bod8P'  `Y8bod8P' `Y8bod8P' d888b    o888o o888o \n";
	std::cout << banner << std::endl;
}

int nameException(const char* functionName) {
	const char* listOfNames[] = { "NtGetTickCount","NtQuerySystemTime","NtdllDefWindowProc_A","NtdllDefWindowProc_W","NtdllDialogWndProc_A","NtdllDialogWndProc_W" };
	for (int i = 0; i < 6; i++) {
		if (strcmp(functionName, listOfNames[i]) == 0) {
			return 0;
		}
	}
	return 1;
}


int main(char *argv,int argc) {
	printBanner();
	PTEB pCurrentTeb = RtlGetThreadEnvironmentBlock();
	PPEB pCurrentPeb = pCurrentTeb->ProcessEnvironmentBlock;
	if (!pCurrentPeb || !pCurrentTeb || pCurrentPeb->OSMajorVersion != 0xA)
		return 0;

	PLDR_DATA_TABLE_ENTRY ntdllModule = NULL;
	PLIST_ENTRY beginningOfTheList = &pCurrentPeb->LoaderData->InMemoryOrderModuleList;
	PLIST_ENTRY cursorOfModules = beginningOfTheList->Flink;
	PLDR_DATA_TABLE_ENTRY currentModule;
	int count = 0;
	while (cursorOfModules != beginningOfTheList) {
		currentModule = (PLDR_DATA_TABLE_ENTRY) ((PBYTE)cursorOfModules - 0x10);
		if (wcscmp(currentModule->BaseDllName.Buffer, L"ntdll.dll") == 0) {
			std::cout << "[FOUND] Loaded Module Index of NTDLL.dll is " << count << std::endl;
			ntdllModule = currentModule;
		}
		count++;
		//std::wcout << currentModule->BaseDllName.Buffer << std::endl;
		cursorOfModules = cursorOfModules->Flink;
	}
	if (ntdllModule) {
		std::cout << "[FOUND] NTDLL.dll is loaded at 0x" << ntdllModule << std::endl;
		PBYTE imageBaseAddressOfNTDLL = (PBYTE) ntdllModule->DllBase;
		PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)imageBaseAddressOfNTDLL;
		PIMAGE_NT_HEADERS imageNTHeaders = (PIMAGE_NT_HEADERS)(imageBaseAddressOfNTDLL + dosHeader->e_lfanew);
		PIMAGE_EXPORT_DIRECTORY imageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(imageBaseAddressOfNTDLL + imageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
		PDWORD nameArray = (PDWORD) (imageBaseAddressOfNTDLL + imageExportDirectory->AddressOfNames);
		PWORD ordinalArray = (PWORD) (imageBaseAddressOfNTDLL + imageExportDirectory->AddressOfNameOrdinals);
		PDWORD addressArray = (PDWORD) (imageBaseAddressOfNTDLL + imageExportDirectory->AddressOfFunctions);
		PCHAR functionName;
		PBYTE functionAddr;
		//Print exported functions
		for (unsigned int i = 0; i < imageExportDirectory->NumberOfNames; i++) {
			functionName = (PCHAR)( imageBaseAddressOfNTDLL + nameArray[i]);
			functionAddr = (PBYTE)(imageBaseAddressOfNTDLL + addressArray[ordinalArray[i]]);
			if (strncmp(functionName, "Nt", 2) == 0){
				//std::cout << "bulundu" << functionName << std::endl;
				if (!(functionAddr[0] == 0x4C && functionAddr[1] == 0x8B && functionAddr[2] == 0xD1 && functionAddr[3] == 0xB8) && nameException(functionName)) {
					std::cout << "[WARNING] Potential Hook : " << functionName << std::endl;
				}
			}
			//std::wcout << functionName << std::endl;
		}


	}
	else {
		std::cout << "[ERROR] Cannot Find NTDLL.dll" << std::endl;
	}
	return 0;
}