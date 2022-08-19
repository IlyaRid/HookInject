#define WIN32_LEAN_AND_MEAN 
#include <winsock2.h> 
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#include <windows.h>
#include <iostream>
#include <tlhelp32.h>
#include <vector>
#include <tchar.h>
#include <ShlObj.h>
#include <comdef.h>

#define BUFSIZE 512

using namespace std;

char dllName[BUFSIZE];
static const char name_lib[] = "Hook.dll";

void get_full_path()
{
    GetModuleFileNameA(NULL, dllName, BUFSIZE);
    size_t len = sizeof(dllName);
    while (dllName[--len] != '\\')
        dllName[len] = 0;
    strncat_s(dllName, name_lib, BUFSIZE);
}

int load_lib_by_pid(DWORD processId) 
{
    get_full_path();

    HANDLE openedProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId); //Открываем существующий объект процесса
    if (openedProcess == NULL) 
    {
        cout << "Error: OpenProcess()" << endl;
        return 0;
    }
    
    HMODULE kernelModule = GetModuleHandleW(L"kernel32.dll"); //среди таблиц импорта требуется найти таблицу, соответствующую kernel32.dll
    if (kernelModule == NULL) 
    {
        cout << "Error: GetModuleHandleW()" << endl;
        CloseHandle(openedProcess);
        return 0;
    }
    
    LPVOID loadLibraryAddr = GetProcAddress(kernelModule, "LoadLibraryA"); //В данной таблице ищется адрес функции, вызов которой нужно отследить
    if (loadLibraryAddr == NULL) 
    {
        cout << "Error: GetProcAddress()" << endl;
        CloseHandle(openedProcess);
        return 0;
    }
    
    LPVOID argLoadLibrary = (LPVOID)VirtualAllocEx(openedProcess, NULL, strlen(dllName), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);//выделяем память под аргумент LoadLibrary,
    if (argLoadLibrary == NULL)                                                                                                    //а именно - строку с адресом инъектируемой dll
    {
        cout << "Error: VirtualAllocEx()" << endl;
        CloseHandle(openedProcess);
        return 0;
    }
    
    int countWrited = WriteProcessMemory(openedProcess, argLoadLibrary, dllName, strlen(dllName), NULL);//адрес перезаписывается на адрес функции, реализующей сам hook
    if (countWrited == NULL)
    {
        cout << "Error: WriteProcessMemory()" << endl;
        CloseHandle(openedProcess);
        return 0;
    }
    
    HANDLE threadID = CreateRemoteThread(openedProcess, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibraryAddr, argLoadLibrary, NULL, NULL);//Загружается dll
    if (threadID == NULL) 
    {
        cout << "Error: CreateRemoteThread()" << endl;
        CloseHandle(openedProcess);
        return 0;
    }
    
    CloseHandle(openedProcess);
    return 1;
}

DWORD get_pid_by_process_name(string processname)
{
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 ProcessEntry;
    DWORD result = NULL;

    if (INVALID_HANDLE_VALUE == hProcessSnap) 
        return(FALSE);
    ProcessEntry.dwSize = sizeof(PROCESSENTRY32); //устанавливаем размер структуру перед её использованием
    
    // Получить информацию о первом процессе,
    // и выходим в случае неудачи
    if (!Process32First(hProcessSnap, &ProcessEntry)) 
    {
        cout << "Error: Process32First()";
        CloseHandle(hProcessSnap);
        return(NULL);
    }

    do 
    {
        _bstr_t b(ProcessEntry.szExeFile);
        const char* c = b;
        if (0 == strcmp(processname.c_str(), c)) 
        {
            result = ProcessEntry.th32ProcessID;
            break;
        }
    } while (Process32Next(hProcessSnap, &ProcessEntry));

    CloseHandle(hProcessSnap);
    return result;
}

int find_text(vector <string> input, int num_arg, string toFind) 
{
    for (int i = 0; i < num_arg; i++)
        if (input[i] == toFind) 
            return i;
    return -1;
}

int main(int argc, char* argv[])
{
    if (!IsUserAnAdmin()) 
    {
        cout << "Administrator privileges required" << endl;
        return 0;
    }
    if (argc != 5) 
    {
        cout << "Uncorrect number of arguments!" << endl;
        return 0;
    }

    vector <string> input;
    for (int i = 0; i < argc - 1; i++)
    {
        input.push_back(argv[i + 1]);
    }

    string pidOrName, funkOrHide;
    int funcRet, itsPid = 0, itsFunc = 0;
    DWORD pid;
   
    if ((funcRet = find_text(input, argc - 2, "-pid")) != -1)
    {
        pidOrName = input[funcRet + 1];
        pid = atoi(pidOrName.c_str());
    }
    else if ((funcRet = find_text(input, argc - 2, "-name")) != -1)
    {
        pidOrName = input[funcRet + 1];
        pid = get_pid_by_process_name(pidOrName);
    }
    else 
    {
        cout << "-pid or -name not found" << endl;
        return 0;
    }

    if (!pid)
    {
        cout << "Process not found" << endl;
        return 0;
    }

    if ((funcRet = find_text(input, argc - 2, "-func")) != -1) 
    {
        funkOrHide = input[funcRet + 1];
        itsFunc = 1;
    }
    else if ((funcRet = find_text(input, argc - 2, "-hide")) != -1)
    {
        funkOrHide = input[funcRet + 1];
    }
    else 
    {
        cout << "-func or -hide not found" << endl;
        return 0;
    }

    string sendStr;
    for (u_int i = 0; i < input.size() - 1; i++) 
    {
        sendStr += input[i];
        sendStr += " ";
    }
    sendStr += input[input.size() - 1];

    //сокет//
    WSADATA wsaData;
    SOCKET ListenSocket, ClientSocket;  // впускающий сокет и сокет для клиентов
    sockaddr_in ServerAddr;  // это будет адрес сервера
    char* recvbuf = new char[BUFSIZE];  // буфер приема

    // Initialize Winsock
    WSAStartup(MAKEWORD(2, 2), &wsaData);
    // Create a SOCKET for connecting to server
    ListenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    // Setup the TCP listening socket
    ServerAddr.sin_family = AF_INET;
    InetPton(AF_INET, _T("127.0.0.1"), &ServerAddr.sin_addr.s_addr);
    ServerAddr.sin_port = htons(9000);

    int error = bind(ListenSocket, (sockaddr*)&ServerAddr, sizeof(ServerAddr));
    if (error == SOCKET_ERROR) 
    {
        cout << "bind failed: " << WSAGetLastError() << endl;
        closesocket(ListenSocket);
        WSACleanup();
        return 1;
    }
    error = listen(ListenSocket, 50);
    if (error == SOCKET_ERROR)
    {
        cout << "listen failed: " << WSAGetLastError() << endl;
        closesocket(ListenSocket);
        WSACleanup();
        return 1;
    }

    if (!load_lib_by_pid(pid))
        return 0;
    
    // Accept a client socket
    ClientSocket = accept(ListenSocket, NULL, NULL);
    error = recv(ClientSocket, recvbuf, BUFSIZE, 0);
    if (error > 0) 
    {
        recvbuf[error] = 0;
        cout << "Received query: " << (char*)recvbuf << endl;
        send(ClientSocket, sendStr.c_str(), strlen(sendStr.c_str()) + 1, 0);
        cout << "Sent answer: " << sendStr.c_str() << endl;
    }
    else 
    {
        cout << "recv failed: " << WSAGetLastError() << endl;
        closesocket(ClientSocket);
        WSACleanup();
        return 0;
    }

    if (itsFunc) while (1)
    {
        error = recv(ClientSocket, recvbuf, BUFSIZE, 0);
        if (error > 0)
        {
            recvbuf[error] = 0;
        }
        else if (error == 0)
        {
            cout << "Connection closing..." << endl;
            break;
        }
        else
        {
            cout << "recv failed: " << WSAGetLastError() << endl;
            closesocket(ClientSocket);
            WSACleanup();
            return 1;
        }
        cout << recvbuf;
    }
    
    closesocket(ClientSocket);
    WSACleanup();
    return 1;
}