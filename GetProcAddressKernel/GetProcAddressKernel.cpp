#include "pch.h"


//注意：需要这两个文件
//dbghelp.dll	
//symsrv.dll

//获取函数地址PDB
ULONG_PTR GetFunctionAddressPDB(HMODULE hMod, const WCHAR * szApiName)
{
	//定义变量
	BYTE memory[0x2000] = { 0 };

	//参数效验
	if (hMod == NULL)return NULL;
	if (szApiName == NULL)return NULL;


	ZeroMemory(memory, sizeof(memory));
	SYMBOL_INFOW * syminfo = (SYMBOL_INFOW *)memory;
	syminfo->SizeOfStruct = sizeof(SYMBOL_INFOW);
	syminfo->MaxNameLen = MAX_SYM_NAME;
	syminfo->ModBase = (ULONG_PTR)hMod;

	if (!SymFromNameW(GetCurrentProcess(), szApiName, syminfo))
	{
		printf("SymFromName %ws returned error : %d\n", szApiName, GetLastError());
		return 0;
	}

	return (ULONG_PTR)syminfo->Address;
}

//符号获取函数地址
PVOID SymGetProcAddress(LPCWSTR szDllName, LPCWSTR szApiName)
{
	//变量定义
	TCHAR symbolPath[0x2000] = { 0 };
	TCHAR szPath[MAX_PATH] = { 0 };

	//参数效验
	if (szDllName == NULL)return NULL;
	if (szApiName == NULL)return NULL;


	GetModuleFileName(0, szPath, ARRAYSIZE(szPath));
	TCHAR * temp = _tcsrchr(szPath, TEXT('\\'));
	if (temp == NULL)return NULL;
	*temp = 0;
	_tcscat_s(symbolPath, TEXT("SRV*"));
	_tcscat_s(symbolPath, szPath);
	_tcscat_s(symbolPath, TEXT("*http://msdl.microsoft.com/download/symbols"));
	SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_FAVOR_COMPRESSED);
	if (!SymInitializeW(GetCurrentProcess(), symbolPath, TRUE))
	{
		return NULL;
	}

	HMODULE hDll = GetModuleHandle(szDllName);
	PVOID lpRet = NULL;
	lpRet = (PVOID)GetFunctionAddressPDB(hDll, szApiName);
	SymCleanup(GetCurrentProcess());

	return lpRet;
}




int main(void)
{

	PVOID lpFuntAddressRet = NULL;
	lpFuntAddressRet = SymGetProcAddress(TEXT("ntkrpamp.exe"), TEXT("ObpAllocateObject"));
	//lpRet = SymGetProcAddress(TEXT("ntdll.dll"), TEXT("RtlDispatchAPC"));
	printf("%p", lpFuntAddressRet);
	return 0;
}