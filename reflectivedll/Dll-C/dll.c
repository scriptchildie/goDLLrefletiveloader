#include <windows.h>
#define DLLEXPORT   __declspec( dllexport )

DLLEXPORT BOOL DllMain( HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved);

BOOL APIENTRY DllMain( HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH:
            MessageBoxA(NULL, "DLL PROCESS ATTACH", "Bingo!", 0);
            break;
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DETACH:
        default:
            break;
    }
    return TRUE;
}