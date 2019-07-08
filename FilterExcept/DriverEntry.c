#include <ntifs.h>
#include <ntimage.h>

#pragma pack(1) //写这个内存以一字节对齐 如果不写是以4字节的对齐的  
typedef struct ServiceDescriptorEntry {//这个结构就是为了管理这个数组而来的 内核api所在的数组 才有这个结构的 这个是ssdt  
	unsigned int *ServiceTableBase;//就是ServiceTable ssdt数组  
	unsigned int *ServiceCounterTableBase; //仅适用于checked build版本 无用  
	unsigned int NumberOfServices;//(ServiceTableBase)数组中有多少个元素 有多少个项  
	unsigned char *ParamTableBase;//参数表基址 我们层传过来的api的参数 占用多少字节 多大  
} ServiceDescriptorTableEntry_t, *PServiceDescriptorTableEntry_t;
#pragma pack()
__declspec(dllimport) ServiceDescriptorTableEntry_t KeServiceDescriptorTable;

typedef struct _SIGNATURE_INFO {
	UCHAR	cSingature;
	int		Offset;
}SIGNATURE_INFO, *PSIGNATURE_INFO;

typedef struct _LDR_DATA_TABLE_ENTRY                         // 24 elements, 0x78 bytes (sizeof) 
{
	/*0x000*/     struct _LIST_ENTRY InLoadOrderLinks;                     // 2 elements, 0x8 bytes (sizeof)   
	/*0x008*/     struct _LIST_ENTRY InMemoryOrderLinks;                   // 2 elements, 0x8 bytes (sizeof)   
	/*0x010*/     struct _LIST_ENTRY InInitializationOrderLinks;           // 2 elements, 0x8 bytes (sizeof)   
	/*0x018*/     VOID*        DllBase;
	/*0x01C*/     VOID*        EntryPoint;
	/*0x020*/     ULONG32      SizeOfImage;
	/*0x024*/     struct _UNICODE_STRING FullDllName;                      // 3 elements, 0x8 bytes (sizeof)   
	/*0x02C*/     struct _UNICODE_STRING BaseDllName;                      // 3 elements, 0x8 bytes (sizeof)   
	/*0x034*/     ULONG32      Flags;
	/*0x038*/     UINT16       LoadCount;
	/*0x03A*/     UINT16       TlsIndex;
	union                                                    // 2 elements, 0x8 bytes (sizeof)   
	{
		/*0x03C*/         struct _LIST_ENTRY HashLinks;                        // 2 elements, 0x8 bytes (sizeof)   
		struct                                               // 2 elements, 0x8 bytes (sizeof)   
		{
			/*0x03C*/             VOID*        SectionPointer;
			/*0x040*/             ULONG32      CheckSum;
		};
	};
	union                                                    // 2 elements, 0x4 bytes (sizeof)   
	{
		/*0x044*/         ULONG32      TimeDateStamp;
		/*0x044*/         VOID*        LoadedImports;
	};
	/*0x048*/     VOID* EntryPointActivationContext;
	/*0x04C*/     VOID*        PatchInformation;
	/*0x050*/     struct _LIST_ENTRY ForwarderLinks;                       // 2 elements, 0x8 bytes (sizeof)   
	/*0x058*/     struct _LIST_ENTRY ServiceTagLinks;                      // 2 elements, 0x8 bytes (sizeof)   
	/*0x060*/     struct _LIST_ENTRY StaticLinks;                          // 2 elements, 0x8 bytes (sizeof)   
	/*0x068*/     VOID*        ContextInformation;
	/*0x06C*/     ULONG32      OriginalBase;
	/*0x070*/     union _LARGE_INTEGER LoadTime;                           // 4 elements, 0x8 bytes (sizeof)   
}LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

ULONG SearchAddressForSign(ULONG uStartBase, ULONG uSearchLength, SIGNATURE_INFO SignatureInfo[5])
{
	UCHAR *p;
	ULONG u_index1, u_index2;

	//ULONG uIndex;
	PIMAGE_DOS_HEADER pimage_dos_header;
	PIMAGE_NT_HEADERS pimage_nt_header;
	PIMAGE_SECTION_HEADER pimage_section_header;

	if (!MmIsAddressValid((PVOID)uStartBase))
	{
		return 0;
	}

	pimage_dos_header = (PIMAGE_DOS_HEADER)uStartBase;
	pimage_nt_header = (PIMAGE_NT_HEADERS)((ULONG)uStartBase + pimage_dos_header->e_lfanew);
	pimage_section_header = (PIMAGE_SECTION_HEADER)((ULONG)pimage_nt_header + sizeof(IMAGE_NT_HEADERS));

	for (u_index1 = 0; u_index1 < pimage_nt_header->FileHeader.NumberOfSections; u_index1++)
	{
		if (pimage_section_header[u_index1].Characteristics & 0x60000000)
		{
			//可读可写的段
			//DbgPrint("SectionName:%s----0x%X----0x%X",pSecHeader[uIndex1].Name,\
			//	pSecHeader[uIndex1].Misc.VirtualSize,uStartBase+pSecHeader[uIndex1].VirtualAddress);
			p = (UCHAR*)uStartBase + pimage_section_header[u_index1].VirtualAddress;
			for (u_index2 = 0; u_index2 < pimage_section_header[u_index1].Misc.VirtualSize; u_index2++)
			{
				if (!MmIsAddressValid((p - SignatureInfo[0].Offset)) ||
					!MmIsAddressValid((p - SignatureInfo[4].Offset)))
				{
					p++;
					continue;
				}
				__try {
					if (*(p - SignatureInfo[0].Offset) == SignatureInfo[0].cSingature&&
						*(p - SignatureInfo[1].Offset) == SignatureInfo[1].cSingature&&
						*(p - SignatureInfo[2].Offset) == SignatureInfo[2].cSingature&&
						*(p - SignatureInfo[3].Offset) == SignatureInfo[3].cSingature&&
						*(p - SignatureInfo[4].Offset) == SignatureInfo[4].cSingature)
					{
						return (ULONG)p;
					}

				}
				__except (EXCEPTION_EXECUTE_HANDLER) {
					DbgPrint("Search error!");
				}
				p++;
			}
		}
	}

	return 0;
}


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

PLDR_DATA_TABLE_ENTRY SearchDriver(PDRIVER_OBJECT pDriverObject, wchar_t *strDriverName)
{
	LDR_DATA_TABLE_ENTRY	*pdata_table_entry, *ptemp_data_table_entry;
	PLIST_ENTRY				plist;
	UNICODE_STRING			str_module_name;

	RtlInitUnicodeString(&str_module_name, strDriverName);

	pdata_table_entry = (LDR_DATA_TABLE_ENTRY*)pDriverObject->DriverSection;
	if (!pdata_table_entry)
	{
		return 0;
	}

	plist = pdata_table_entry->InLoadOrderLinks.Flink;

	while (plist != &pdata_table_entry->InLoadOrderLinks)
	{
		ptemp_data_table_entry = (LDR_DATA_TABLE_ENTRY *)plist;

		//KdPrint(("%wZ",&pTempDataTableEntry->BaseDllName));
		if (0 == RtlCompareUnicodeString(&ptemp_data_table_entry->BaseDllName, &str_module_name, FALSE))
		{
			return ptemp_data_table_entry;
		}

		plist = plist->Flink;
	}

	return 0;
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

/////////////////////////////////////////////////////////////////////////////////////////////////////
//global
PDRIVER_OBJECT	g_LocalDriverObj;
BOOLEAN			g_HookSuccess;
ULONG			g_fnRtlDispatchException;
ULONG			g_JmpOrigDisException;
UCHAR			g_cDisExceptionCode[5];
ULONG			g_JmpNtOpenprocess;


VOID FilterNtOpenProcess()
{
	KdPrint(("FilterNtOpenProcess-------%s",(char*)((ULONG)PsGetCurrentProcess()+0x16c)));
}

VOID __declspec(naked) NewNtOpenProcess()
{
	__asm
	{
		pushad
		pushfd

		call	FilterNtOpenProcess

		popfd
		popad
		mov		edi,edi
		push	ebp
		mov		ebp,esp
		jmp		g_JmpNtOpenprocess
	}
}

ULONG __stdcall FilterRtlDispatchException(IN PEXCEPTION_RECORD ExceptionRecord, IN PCONTEXT Context)
{
	if (ExceptionRecord->ExceptionAddress == (PVOID)KeServiceDescriptorTable.ServiceTableBase[190])
	{
		Context->Eip = (ULONG)NewNtOpenProcess;
		KdPrint(("<Exception Address>:%X  <Seh CAllBACK>:%X  Except code:%X", ExceptionRecord->ExceptionAddress, Context->Eip, ExceptionRecord->ExceptionCode));
		return 1;
	}
	return 0;
}

VOID __declspec(naked) NewRtlDispatchException()
{
	__asm
	{
		mov		edi,edi
		push	ebp
		mov		ebp,esp

		pushad
		pushfd

		push	[ebp+0xc];
		push	[ebp+0x8]
		call	FilterRtlDispatchException
		test	eax,eax
		jz		__SafeExit

		popfd
		popad

		mov		esp,ebp
		pop		ebp


		mov		eax,0x1
		retn	0x8

__SafeExit:
		popfd
		popad
		
		mov		esp, ebp
		pop		ebp

		mov		edi,edi
		push	ebp
		mov		ebp,esp

		jmp		g_JmpOrigDisException
	}
}

VOID UNHookRtlDisPatchException()
{
	if (g_HookSuccess)
	{
		Res_HookFunction(g_fnRtlDispatchException, g_cDisExceptionCode, 0x5);
	}
}

VOID HookRtlDisPatchException()
{
	PLDR_DATA_TABLE_ENTRY	Ldr;
	SIGNATURE_INFO			SignCode[5] = { {0x84,10},{0xC0,9},{0x57,2},{0x53,1},{0xE8,0} };
	g_HookSuccess = FALSE;
	Ldr = SearchDriver(g_LocalDriverObj, L"ntoskrnl.exe");
	if (!Ldr)
	{
		return;
	}
	g_fnRtlDispatchException = SearchAddressForSign((ULONG)Ldr->DllBase, Ldr->SizeOfImage, SignCode);
	if (!MmIsAddressValid((PVOID)g_fnRtlDispatchException))
	{
		return;
	}
	g_fnRtlDispatchException = g_fnRtlDispatchException + *(ULONG*)(g_fnRtlDispatchException + 1) + 5;
	g_JmpOrigDisException = g_fnRtlDispatchException + 5;
	KdPrint(("%X", g_fnRtlDispatchException));
	g_HookSuccess = Jmp_HookFunction(g_fnRtlDispatchException, (ULONG)NewRtlDispatchException, g_cDisExceptionCode);
}


VOID SetMonitor(ULONG address)
{
	__asm
	{
		mov eax,address
		mov dr0,eax
		mov eax,0x2
		mov dr7,eax
	}
}

VOID DelMonitor()
{
	__asm
	{
		mov eax, 0
		mov dr0, eax
		mov dr7, eax
	}
}

VOID DriverUnLoad(PDRIVER_OBJECT pDrverObject)
{
	DelMonitor();
	UNHookRtlDisPatchException();
	KdPrint(("驱动卸载成功！"));
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDrverObject, PUNICODE_STRING usRegPath)
{
	KdPrint(("驱动加载成功！"));
	g_LocalDriverObj = pDrverObject;
	HookRtlDisPatchException();
	g_JmpNtOpenprocess = KeServiceDescriptorTable.ServiceTableBase[190] + 0x5;
	SetMonitor(KeServiceDescriptorTable.ServiceTableBase[190]);
	pDrverObject->DriverUnload = DriverUnLoad;
	return STATUS_SUCCESS;
}