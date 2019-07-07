#include <iostream>
#include <windows.h>

using std::cout;
using std::endl;

LONG NTAPI VeHandler(struct _EXCEPTION_POINTERS *ExceptionInfo)
{
	static DWORD Eax;
	ExceptionInfo->ContextRecord->Eax = (DWORD)&Eax;
	cout << "VeHandler:" << std::hex << std::uppercase << ExceptionInfo->ContextRecord->Eax << endl;
	return EXCEPTION_CONTINUE_EXECUTION;
}

LONG NTAPI VcHandler(struct _EXCEPTION_POINTERS *ExceptionInfo)
{
	static DWORD Eax;
	ExceptionInfo->ContextRecord->Eax = (DWORD)&Eax;
	cout << "VcHandler:" << std::hex << std::uppercase << ExceptionInfo->ContextRecord->Eax << endl;
	return EXCEPTION_CONTINUE_EXECUTION;
}


LONG NTAPI SefHandler(struct _EXCEPTION_POINTERS *ExceptionInfo)
{
	static DWORD Eax;
	ExceptionInfo->ContextRecord->Eax = (DWORD)&Eax;
	cout << "SefHandler:" << std::hex << std::uppercase << ExceptionInfo->ContextRecord->Eax << endl;
	return EXCEPTION_CONTINUE_EXECUTION;
}

int main()
{
	int address = 0;
	//AddVectoredExceptionHandler(TRUE, VeHandler);
	//AddVectoredContinueHandler(TRUE, VcHandler);
	//__try
	//{
	//	*(ULONG_PTR*)address = 0;
	//}
	//__except (1)
	//{
	//	cout << "seh" << endl;
	//	cout << "Seh" << endl;
	//}
	SetUnhandledExceptionFilter(SefHandler);
	__asm
	{
		mov eax, 0
		mov[eax], 0
	}
	getchar();
	return 0;
}