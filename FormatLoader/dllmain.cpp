#include "pch.h"

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ulReason, LPVOID lpReserved)
{
	switch (ulReason)
	{
	case DLL_PROCESS_ATTACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

