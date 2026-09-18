// File: main.hpp
// Author: NepoOwen
// https://github.com/NepoOwen/trove-xigncode

#include "challenge.hpp"
#include <cstdint>

DWORD WINAPI SetupThread(LPVOID lpParam) {
	auto t = detail::client::helper::freeze(); // freeze
    xigncode::initialize(); // xigncode
	detail::client::helper::unfreeze(t); // unfreeze
    return 0;
}

extern "C" __declspec(dllexport) BOOL WINAPI clientdll(HMODULE hModule, void* config = nullptr) {
	HANDLE thread = CreateThread(nullptr, 0, SetupThread, nullptr, 0, nullptr);
	if (thread) { CloseHandle(thread); return 1; }
	return 0;
}