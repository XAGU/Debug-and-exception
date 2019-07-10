#include <ntifs.h>
#include <ntimage.h>



typedef NTKERNELAPI NTSTATUS (*PSGETCONTEXTTHREAD)(
	__in PETHREAD Thread,
	__inout PCONTEXT ThreadContext,
	__in KPROCESSOR_MODE Mode
);

typedef NTKERNELAPI NTSTATUS(*PSSETCONTEXTTHREAD)(
	__in PETHREAD Thread,
	__in PCONTEXT ThreadContext,
	__in KPROCESSOR_MODE Mode
);


void PageProtectOn()
{
	__asm {//恢复内存保护  
		mov  eax, cr0
		or eax, 10000h
		mov  cr0, eax
		sti
	}
}

void PageProtectOff()
{
	__asm {//去掉内存保护
		cli
		mov  eax, cr0
		and  eax, not 10000h
		mov  cr0, eax
	}
}


BOOLEAN	Jmp_HookFunction(
	IN ULONG Destination,
	IN ULONG Source,
	IN UCHAR *Ori_Code
)
{
	ULONG	jmp_offset;
	UCHAR	jmp_code[5] = { 0xE9 };

	KSPIN_LOCK lock;
	KIRQL irql;

	if (Destination == 0 || Source == 0)
	{
		DbgPrint("Params error!");
		return FALSE;
	}
	RtlCopyMemory(Ori_Code, (PVOID)Destination, 5);
	jmp_offset = Source - Destination - 5;
	*(ULONG*)&jmp_code[1] = jmp_offset;

	KeInitializeSpinLock(&lock);
	KeAcquireSpinLock(&lock, &irql);

	PageProtectOff();
	RtlCopyMemory((PVOID)Destination, jmp_code, 5);
	PageProtectOn();

	KeReleaseSpinLock(&lock, irql);

	return TRUE;
}

VOID Res_HookFunction(
	IN ULONG	Destination,
	IN UCHAR	*Ori_Code,
	IN ULONG	Length
)
{
	KSPIN_LOCK lock;
	KIRQL irql;

	if (Destination == 0 || Ori_Code == 0) { return; }

	KeInitializeSpinLock(&lock);
	KeAcquireSpinLock(&lock, &irql);

	PageProtectOff();
	RtlCopyMemory((PVOID)Destination, Ori_Code, Length);
	PageProtectOn();

	KeReleaseSpinLock(&lock, irql);
}




//////////////////////////////////////////////////////////////////////////////////////
//global
PSGETCONTEXTTHREAD		PsGetContextThread;
ULONG					g_JmpGetContextThread;
ULONG					g_bHookGetContextThreadSuccess;
UCHAR					g_cGetContextThread[5];

PSSETCONTEXTTHREAD		PsSetContextThread;
ULONG					g_JmpSetContextThread;
ULONG					g_bHookSetContextThreadSuccess;
UCHAR					g_cSetContextThread[5];


VOID __stdcall FiliterPsGetSetContextThread(__in PETHREAD Thread,
	__in PCONTEXT ThreadContext,
	__in KPROCESSOR_MODE Mode)
{
	if (Mode == UserMode)
	{
		KdPrint(("UserMode !"));
	}
	else if (Mode == KernelMode)
	{
		KdPrint(("KernelMode !"));
	}
	ULONG	Process;
	if (Thread == 0) { return ; }

	Process = *(ULONG*)((ULONG)Thread + 0x150);
	if (Process == 0) { return ; }
	KdPrint(("%s", Process + 0x16c));
	KdPrint(("CALLED !%X",Thread));
}


__declspec(naked) VOID NewPsGetContextThread()
{
	__asm
	{
		pushad
		pushfd

		mov			edi, edi
		push		ebp
		mov			ebp,esp

		push		[ebp+0x10]
		push		[ebp+0xc]
		push		[ebp+0x8]

		call		FiliterPsGetSetContextThread

		mov			esp,ebp
		pop			ebp

		popfd
		popad
		
		mov			edi,edi
		push		ebp
		mov			ebp,esp
		jmp			g_JmpGetContextThread
	}
}

__declspec(naked) VOID NewPsSetContextThread()
{
	__asm
	{
		pushad
		pushfd

		push[ebp + 0x10]
		push[ebp + 0xc]
		push[ebp + 0x8]

		call		FiliterPsGetSetContextThread

		popfd
		popad

		mov			edi, edi
		push		ebp
		mov			ebp, esp
		jmp			g_JmpSetContextThread
	}
}


VOID HookGetSetContextThread()
{
	UNICODE_STRING			usGetContext;
	UNICODE_STRING			usSetContext;

	RtlInitUnicodeString(&usGetContext, L"PsGetContextThread");
	RtlInitUnicodeString(&usSetContext, L"PsSetContextThread");

	PsGetContextThread = (PSGETCONTEXTTHREAD)MmGetSystemRoutineAddress(&usGetContext);
	PsSetContextThread = (PSSETCONTEXTTHREAD)MmGetSystemRoutineAddress(&usSetContext);

	g_JmpGetContextThread = (ULONG)PsGetContextThread + 0x5;
	g_JmpSetContextThread = (ULONG)PsSetContextThread + 0x5;

	g_bHookGetContextThreadSuccess = Jmp_HookFunction((ULONG)PsGetContextThread, (ULONG)NewPsGetContextThread, g_cGetContextThread);
	g_bHookSetContextThreadSuccess = Jmp_HookFunction((ULONG)PsSetContextThread, (ULONG)NewPsSetContextThread, g_cSetContextThread);


}

VOID UnHookGetSetContextThread()
{
	if (g_bHookGetContextThreadSuccess)
	{
		Res_HookFunction((ULONG)PsGetContextThread, g_cGetContextThread, 5);
	}
	if (g_bHookSetContextThreadSuccess)
	{
		Res_HookFunction((ULONG)PsSetContextThread, g_cSetContextThread, 5);
	}
}


VOID DriverUnLoad(PDRIVER_OBJECT pDrverObject)
{
	UnHookGetSetContextThread();
	KdPrint(("驱动卸载成功！"));
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDrverObject, PUNICODE_STRING usRegPath)
{

	KdPrint(("驱动加载成功！"));
	HookGetSetContextThread();
	pDrverObject->DriverUnload = DriverUnLoad;
	return STATUS_SUCCESS;
}