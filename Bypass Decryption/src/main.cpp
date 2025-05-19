#include <iostream>

uintptr_t GetClActiveClient()
{
    uintptr_t codecave = base_address + 0x79339A2;
    // printf("codecave -> %p\n", codecave);
    uintptr_t final_func = base_address + 0x79339A9;//few byte after codecave for the rest of the function
    // printf("final_func -> %p\n", final_func);
    uintptr_t originalFunction = base_address + 0x1E3046B;//add rsp,68 ClActiveClient //C6 80 69 2E 01 00 00 48 83 C4 68 5B 5D C3
    // printf("originalFunction -> %p\n", originalFunction);
    uintptr_t copy_func = base_address + 0x79339E0;//code cave
    ///   printf("copy_func -> %p\n", copy_func);


       //sig from func before the return  48 83 C4 68 5B 5D C3 = jmp codecave
    int32_t relativeOffset = (int32_t)(codecave - (originalFunction + 5));//5 = jmp size
    BYTE jumpToShell[5];
    jumpToShell[0] = 0xE9;// jmp =   jumpToShell[0]
    memcpy(&jumpToShell[1], &relativeOffset, sizeof(relativeOffset));//jumpToShell[1] = relativeOffset(so our addr)
    driver.WriteProcessMemory((PVOID)originalFunction, jumpToShell, sizeof(jumpToShell));

    //codecave  addr = mov [copy_func], rax
    int32_t relativeOffset2 = (int32_t)(copy_func - (codecave + 7));
    BYTE MovToShell2[7];
    MovToShell2[0] = 0x48;//mov 
    MovToShell2[1] = 0x89;
    MovToShell2[2] = 0x05;
    CALL(memcpy, &MovToShell2[3], &relativeOffset2, sizeof(relativeOffset2));
    driver.WriteProcessMemory((PVOID)codecave, MovToShell2, sizeof(MovToShell2));


    // write final_func = 48 83 C4 68 5B 5D C3
    BYTE final_shell[] = { 0x48, 0x83, 0xC4, 0x68, 0x5B, 0x5D, 0xC3 };
    driver.WriteProcessMemory((PVOID)final_func, final_shell, sizeof(final_shell));


    uintptr_t returnValue = driver.rpm<uintptr_t>(base_address + 0x79339E0);
    // printf("value : %p\n", copy_func);

    return returnValue;
}

int main() {
	
	return 0;
}