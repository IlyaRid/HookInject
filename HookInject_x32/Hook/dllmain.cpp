// dllmain.cpp : Определяет точку входа для приложения DLL.
#include "pch.h"
#include <windows.h>
#include <detours.h>
#include <stdio.h>
#include <iostream>

#define WIN32_LEAN_AND_MEAN
#include <WinSock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "ws2_32.lib")
#pragma warning(disable  : 4996);
#define BUFSIZE 512

using namespace std;

CHAR funName[BUFSIZE];
SOCKET ConnectSocket;
bool gConnect = FALSE;

char timer[BUFSIZE] = { 0 };
char dt[BUFSIZE] = { 0 };

string  full_path;
wstring w_full_path;

extern "C" void hook_func();
extern "C" LPVOID DynamicTarget = NULL;

void send_msg()
{
    if (gConnect)
    {
        CHAR send_msg[BUFSIZE];
        SYSTEMTIME st;
        GetLocalTime(&st);
        sprintf_s(dt, "%d-%02d-%02d %02d:%02d:%02d\n", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
        if (timer == NULL || strcmp(dt, timer))
        {
            sprintf_s(timer, "%d-%02d-%02d %02d:%02d:%02d\n", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
            sprintf_s(send_msg, "%s()\tTime: %s", funName, timer);
            send(ConnectSocket, send_msg, strlen(send_msg) + 1, 0);
        }

        gConnect = FALSE;
    }
}

int tcp_connect()
{
	WSAData wsaData;
	sockaddr_in ServerAddr;

	WSAStartup(MAKEWORD(2, 2), &wsaData);
	ConnectSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	ServerAddr.sin_family = AF_INET;
	ServerAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
	ServerAddr.sin_port = htons(9000);

	int err = connect(ConnectSocket, (sockaddr*)&ServerAddr, sizeof(ServerAddr));
	if (err == SOCKET_ERROR)
	{
		closesocket(ConnectSocket);
		WSACleanup();
		return 0;
	}
	return 1;
}

//функция-перехватчик
extern "C" VOID DynamicDetour()
{
	gConnect = TRUE;
	send_msg();
}

HANDLE(WINAPI* pCreateFileA) (LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) = CreateFileA;
HANDLE(WINAPI* pCreateFileW) (LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) = CreateFileW;
HANDLE(WINAPI* pFindFirstFileW) (LPCWSTR lpFileName, LPWIN32_FIND_DATA lpFindFileData) = FindFirstFileW;
HANDLE(WINAPI* pFindFirstFileA)(LPCSTR lpFileName, LPWIN32_FIND_DATAA lpFindFileData) = FindFirstFileA;
BOOL(WINAPI* pFindNextFileW) (HANDLE hFindFile, LPWIN32_FIND_DATA lpFindFileData) = FindNextFileW;
BOOL(WINAPI* pFindNextFileA) (HANDLE hFindFile, LPWIN32_FIND_DATAA  lpFindFileData) = FindNextFileA;
HANDLE(WINAPI* pFindFirstFileExA) (LPCSTR lpFileName, FINDEX_INFO_LEVELS fInfoLevelId, LPVOID lpFindFileData, FINDEX_SEARCH_OPS  fSearchOp, LPVOID lpSearchFilter, DWORD dwAdditionalFlags) = FindFirstFileExA;
HANDLE(WINAPI* pFindFirstFileExW) (LPCWSTR lpFileName, FINDEX_INFO_LEVELS fInfoLevelId, LPVOID lpFindFileData, FINDEX_SEARCH_OPS  fSearchOp, LPVOID lpSearchFilter, DWORD dwAdditionalFlags) = FindFirstFileExW;

HANDLE WINAPI MyCreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
{
	if (lpFileName == full_path) 
	{
		return INVALID_HANDLE_VALUE;
	}
	return pCreateFileA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

HANDLE WINAPI MyCreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
{
	if (lpFileName == w_full_path)
	{
		return INVALID_HANDLE_VALUE;
	}
	return pCreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

HANDLE WINAPI MyFindFirstFileA(LPCSTR lpFileName, LPWIN32_FIND_DATAA lpFindFileData)
{
	if (lpFileName == full_path) 
	{
		return INVALID_HANDLE_VALUE;
	}
	return pFindFirstFileA(lpFileName, lpFindFileData);
}

HANDLE WINAPI MyFindFirstFileW(LPCWSTR lpFileName, LPWIN32_FIND_DATA lpFindFileData)
{
	if (lpFileName == w_full_path)
	{
		return INVALID_HANDLE_VALUE;
	}
	return pFindFirstFileW(lpFileName, lpFindFileData);
}

BOOL WINAPI MyFindNextFileA(HANDLE hFindFile, LPWIN32_FIND_DATAA lpFindFileData)
{
	bool ret = pFindNextFileA(hFindFile, lpFindFileData);
	if (lpFindFileData->cFileName == full_path) 
	{
		ret = pFindNextFileA(hFindFile, lpFindFileData);
	}
	return ret;
}

BOOL WINAPI MyFindNextFileW(HANDLE hFindFile, LPWIN32_FIND_DATAW lpFindFileData)
{
	bool ret = pFindNextFileW(hFindFile, lpFindFileData);
	if (lpFindFileData->cFileName == w_full_path) 
	{
		ret = pFindNextFileW(hFindFile, lpFindFileData);
	}
	return ret;
}

HANDLE MyFindFirstFileExW(LPCWSTR a0, FINDEX_INFO_LEVELS a1, LPWIN32_FIND_DATAW a2, FINDEX_SEARCH_OPS a3, LPVOID a4, DWORD a5)
{
	HANDLE ret = pFindFirstFileExW(a0, a1, a2, a3, a4, a5);
	if (a2->cFileName == w_full_path)
	{
		ret = INVALID_HANDLE_VALUE;
	}
	return ret;
}

HANDLE MyFindFirstFileExA(LPCSTR a0, FINDEX_INFO_LEVELS a1, LPWIN32_FIND_DATAA a2, FINDEX_SEARCH_OPS a3, LPVOID a4, DWORD a5)
{
	HANDLE ret = pFindFirstFileExA(a0, a1, a2, a3, a4, a5);
	if (a2->cFileName == full_path)
	{
		ret = INVALID_HANDLE_VALUE;
	}
	return ret;
}

int hide_file(string& fileName)
{
	LONG error;
	full_path = fileName;
	w_full_path = wstring(full_path.begin(), full_path.end());

	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourAttach(&(PVOID&)pCreateFileA, MyCreateFileA);
	error = DetourTransactionCommit();
	if (error != NO_ERROR)
		return -1;

	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourAttach(&(PVOID&)pCreateFileW, MyCreateFileW);
	error = DetourTransactionCommit();
	if (error != NO_ERROR)
		return -1;

	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourAttach(&(PVOID&)pFindFirstFileW, MyFindFirstFileW);
	error = DetourTransactionCommit();
	if (error != NO_ERROR)
		return -1;

	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourAttach(&(PVOID&)pFindFirstFileA, MyFindFirstFileA);
	error = DetourTransactionCommit();
	if (error != NO_ERROR)
		return -1;

	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourAttach(&(PVOID&)pFindNextFileW, MyFindNextFileW);
	error = DetourTransactionCommit();
	if (error != NO_ERROR)
		return -1;

	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourAttach(&(PVOID&)pFindNextFileA, MyFindNextFileA);
	error = DetourTransactionCommit();
	if (error != NO_ERROR)
		return -1;

	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourAttach(&(PVOID&)pFindFirstFileExW, MyFindFirstFileExW);
	error = DetourTransactionCommit();
	if (error != NO_ERROR)
		return -1;

	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourAttach(&(PVOID&)pFindFirstFileExA, MyFindFirstFileExA);
	error = DetourTransactionCommit();
	if (error != NO_ERROR)
		return -1;

	return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
	char* recvbuf = new char[BUFSIZE];  // буфер приема
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH: // Инициализация процесса
    {
        char param[BUFSIZE];
        if (!tcp_connect()) break;

        sprintf(recvbuf, "OK");
        send(ConnectSocket, recvbuf, strlen(recvbuf) + 1, 0);
        recv(ConnectSocket, recvbuf, BUFSIZE, 0);

        int count = 0, pos = 0, paramPos = 0;
        for (int i = 0; i < strlen(recvbuf); i++) 
		{
            if (recvbuf[i] == ' ') 
			{
                count++;
                pos = 0;
            }
            switch (count) 
			{
            case 2:
                if (pos != 0)
                    param[pos - 1] = recvbuf[i];
                paramPos = pos;
                pos++;
                break;
            case 3:
                if (pos != 0)
                    funName[pos - 1] = recvbuf[i];
                pos++;
            default:
                break;
            }
        }
        param[paramPos] = '\0';
        funName[pos] = '\0';

        if (!strcmp(param, "-func"))
        {
            DynamicTarget = DetourFindFunction("kernel32.dll", funName); //получаем адрес оригинальной функции
            DetourTransactionBegin(); //объявления обхода 
            DetourUpdateThread(GetCurrentThread());//обновления потока
            DetourAttach(&(PVOID&)DynamicTarget, hook_func);//производит подмену оригинальной функции на нашу

            LONG err = DetourTransactionCommit();
            if (err != NO_ERROR)
			{
                char send_msg[BUFSIZE];
                sprintf_s(send_msg, "ERROR: DetourTransactionCommit() - %d\n", err);
                send(ConnectSocket, send_msg, strlen(send_msg) + 1, 0);
                return 1;
            }
        }
        else if (!strcmp(param, "-hide")) 
		{
            string hideName(funName);
            hide_file(hideName);
            closesocket(ConnectSocket);
            WSACleanup();
            return 1;
        }
        break;
    }
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}