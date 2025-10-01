/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include <windows.h>
#include <userenv.h>
#include <wtsapi32.h>

int wmain(int argc, wchar_t * argv[]);
void WINAPI ServiceMain(DWORD argc, LPWSTR *argv);
void WINAPI ServiceCtrlHandler(DWORD Opcode);

SERVICE_STATUS m_ServiceStatus = {SERVICE_WIN32_OWN_PROCESS, SERVICE_STOPPED, 0, NO_ERROR, 0, 0, 0};
SERVICE_STATUS_HANDLE m_ServiceStatusHandle = NULL;
HANDLE m_pyrsvcRunning;
PWCHAR z_cmdLine, z_logFile;
const WCHAR PYRSVC_NAME[] = L"pyrsvc", PYRSVC_PRE_CMD[] = L"cmd.exe /c \"", PYRSVC_POST_CMD[] = L"\" > ", PYRSVC_END_CMD[] = L" 2>&1";

int wmain(int argc, wchar_t * argv[])
{
	int status = ERROR_SERVICE_NOT_IN_EXE;
	const SERVICE_TABLE_ENTRY DispatchTable[]= {{(LPWSTR) PYRSVC_NAME, ServiceMain}, {NULL, NULL}};
	if(argc == 3)
	{
		if(z_cmdLine = _wcsdup(argv[1]))
		{
			if(z_logFile = _wcsdup(argv[2]))
			{
				if(m_pyrsvcRunning = CreateEvent(NULL, TRUE, FALSE, NULL))
				{
					if(StartServiceCtrlDispatcher(DispatchTable))
						status = ERROR_SUCCESS;
					else status = GetLastError();
					CloseHandle(m_pyrsvcRunning);
				}
				free(z_logFile);
			}
			free(z_cmdLine);
		}
	}
	return status;
}

void WINAPI ServiceMain(DWORD argc, LPWSTR *argv)
{
	STARTUPINFO si = {0};
	PROCESS_INFORMATION pi;
	PWCHAR arguments;
	DWORD size;
	HANDLE hUser;
	LPVOID env;
	si.cb = sizeof(STARTUPINFO);
	if(m_ServiceStatusHandle = RegisterServiceCtrlHandler(PYRSVC_NAME, ServiceCtrlHandler))
	{
		m_ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
		SetServiceStatus(m_ServiceStatusHandle, &m_ServiceStatus);
		m_ServiceStatus.dwCurrentState = SERVICE_RUNNING;
		m_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
		SetServiceStatus(m_ServiceStatusHandle, &m_ServiceStatus);

		size = ((ARRAYSIZE(PYRSVC_PRE_CMD) - 1) + lstrlen(z_cmdLine) + (ARRAYSIZE(PYRSVC_POST_CMD) - 1) + lstrlen(z_logFile) + (ARRAYSIZE(PYRSVC_END_CMD) - 1) + 1) * sizeof(WCHAR);
		if(arguments = (PWCHAR) malloc(size))
		{
			memset(arguments, '\0', size);
			wcscat_s(arguments, size, PYRSVC_PRE_CMD);
			wcscat_s(arguments, size, z_cmdLine);
			wcscat_s(arguments, size, PYRSVC_POST_CMD);
			wcscat_s(arguments, size, z_logFile);
			wcscat_s(arguments, size, PYRSVC_END_CMD);
			if(WTSQueryUserToken(WTSGetActiveConsoleSessionId(), &hUser))
			{
				if(CreateEnvironmentBlock(&env, hUser, FALSE))
				{
					if(CreateProcessAsUser(hUser, NULL, arguments, NULL, NULL, FALSE, CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT, NULL, NULL, &si, &pi))
					{
						CloseHandle(pi.hThread);
						CloseHandle(pi.hProcess);
					}
					DestroyEnvironmentBlock(env);
				}
				CloseHandle(hUser);
			}
			free(arguments);
		}
		WaitForSingleObject(m_pyrsvcRunning, INFINITE);
		m_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
		SetServiceStatus(m_ServiceStatusHandle, &m_ServiceStatus);
	}
}

void WINAPI ServiceCtrlHandler(DWORD Opcode)
{
	if((Opcode == SERVICE_CONTROL_STOP) || (Opcode == SERVICE_CONTROL_SHUTDOWN))
	{
		m_ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
		SetServiceStatus (m_ServiceStatusHandle, &m_ServiceStatus);
		SetEvent(m_pyrsvcRunning);
	}
}
