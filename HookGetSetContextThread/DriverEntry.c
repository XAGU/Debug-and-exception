#include <ntifs.h>
#include <ntimage.h>

#if defined(_AMD64_)

FORCEINLINE
VOID
ProbeForReadSmallStructure(
	IN PVOID Address,
	IN SIZE_T Size,
	IN ULONG Alignment
)

/*++

Routine Description:

	Probes a structure for read access whose size is known at compile time.

	N.B. A NULL structure address is not allowed.

Arguments:

	Address - Supples a pointer to the structure.

	Size - Supplies the size of the structure.

	Alignment - Supplies the alignment of structure.

Return Value:

	None

--*/

{

	ASSERT((Alignment == 1) || (Alignment == 2) ||
		(Alignment == 4) || (Alignment == 8) ||
		(Alignment == 16));

	if ((Size == 0) || (Size >= 0x10000)) {

		ASSERT(0);

		ProbeForRead(Address, Size, Alignment);

	}
	else {
		if (((ULONG_PTR)Address & (Alignment - 1)) != 0) {
			ExRaiseDatatypeMisalignment();
		}

		if ((PUCHAR)Address >= (UCHAR * const)MM_USER_PROBE_ADDRESS) {
			Address = (UCHAR * const)MM_USER_PROBE_ADDRESS;
		}

		_ReadWriteBarrier();
		*(volatile UCHAR *)Address;
	}
}

#else

#define ProbeForReadSmallStructure(Address, Size, Alignment) {               \
    ASSERT(((Alignment) == 1) || ((Alignment) == 2) ||                       \
           ((Alignment) == 4) || ((Alignment) == 8) ||                       \
           ((Alignment) == 16));                                             \
    if ((Size == 0) || (Size > 0x10000)) {                                   \
        ASSERT(0);                                                           \
        ProbeForRead(Address, Size, Alignment);                              \
    } else {                                                                 \
        if (((ULONG_PTR)(Address) & ((Alignment) - 1)) != 0) {               \
            ExRaiseDatatypeMisalignment();                                   \
        }                                                                    \
        if ((ULONG_PTR)(Address) >= (ULONG_PTR)MM_USER_PROBE_ADDRESS) {      \
            *(volatile UCHAR * const)MM_USER_PROBE_ADDRESS = 0;              \
        }                                                                    \
    }                                                                        \
}

#endif

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
	//[1956] setThreadContext(394, 5EC, 12FCFBB4). dr0=0 dr1=0 dr2=0 dr3=0 dr7=400
	if (!MmIsAddressValid(ThreadContext))
	{
		KdPrint(("ThreadContext Error"));
		return ;
	}
	KdPrint(("setThreadContext(%X, %X, %X). dr0=%X dr1=%X dr2=%X dr3=%X dr7=%X",
		Thread, ThreadContext, Mode,ThreadContext->Dr0, ThreadContext->Dr1, ThreadContext->Dr2, ThreadContext->Dr3, ThreadContext->Dr7));
	ULONG	Process;
	if (!MmIsAddressValid(Thread))
	{
		return;
	}
	Process = *(ULONG*)((ULONG)Thread + 0x150);
	KdPrint(("%X", Process));
	if (Process == 0) { return; }
	__try
	{
		if (Mode == UserMode)
		{
			ProbeForReadSmallStructure(ThreadContext, sizeof(CONTEXT), PROBE_ALIGNMENT(CONTEXT));
			KdPrint(("UserMode !"));
		}
		else if(Mode == KernelMode)
		{
			KdPrint(("Not UserMode !"));
		}
		if (strstr((char*)(Process + 0x16c),"game.exe") != NULL)
		{
			KdPrint(("%s", Process + 0x16c));
			if (strstr((char*)((ULONG)PsGetCurrentProcess()+0x16c),"ollydbg") != NULL)
			{
				KdPrint(("ollydbg !"));
				return;
			}
			if (ThreadContext->ContextFlags|CONTEXT_DEBUG_REGISTERS)
			{
				KdPrint(("~CONTEXT_DEBUG_REGISTERS !"));
				ThreadContext->ContextFlags = ~CONTEXT_DEBUG_REGISTERS;
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		KdPrint(("EXCEPTION_EXECUTE_HANDLER !"));
		return;
	}
}


__declspec(naked) VOID NewPsGetContextThread()
{
	__asm
	{

		push		[esp + 0x10]
		push		[esp + 0xc]
		push		[esp+0x8]

		call		FiliterPsGetSetContextThread


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


		push		[esp + 0x10]
		push		[esp + 0xc]
		push		[esp + 0x8]

		call		FiliterPsGetSetContextThread


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