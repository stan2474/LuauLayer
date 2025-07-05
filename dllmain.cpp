#include "hooks.h"
#include <Windows.h>
void __declspec(dllexport) import() {} // https://github.com/lrre-foss/lure/blob/7853281b0389eb0ab7e79f024840cd4bd6b162af/Lure/dllmain.cpp#L36 method
void main() {
    InstallLuaHook();
}
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH)
    {
        main();
    }
    return TRUE;
}