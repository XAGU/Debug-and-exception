#include "inc.h"

#pragma pack(1)
typedef struct ServiceDescriptorEntry {
	unsigned int *ServiceTableBase;
	unsigned int *ServiceCounterTableBase; //仅适用于checked build版本
	unsigned int NumberOfServices;
	unsigned char *ParamTableBase;
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

ULONG GetAddress(ULONG uAddress, UCHAR *Signature, int flag)
{
	ULONG	index;
	UCHAR	*p;
	ULONG	uRetAddress;

	if (uAddress == 0) { return 0; }

	p = (UCHAR*)uAddress;
	for (index = 0; index < 0x3000; index++)
	{
		if (*p == Signature[0] &&
			*(p + 1) == Signature[1] &&
			*(p + 2) == Signature[2] &&
			*(p + 3) == Signature[3] &&
			*(p + 4) == Signature[4])
		{
			if (flag == 0)
			{
				uRetAddress = (ULONG)(p + 4) + *(ULONG*)(p + 5) + 5;
				return uRetAddress;
			}
			else if (flag == 1)
			{
				uRetAddress = *(ULONG*)(p + 5);
				return uRetAddress;
			}
			else if (flag == 2) {
				uRetAddress = (ULONG)(p + 4);
				return uRetAddress;
			}
			else if (flag == 3) {
				uRetAddress = (ULONG)(p + 5);
				return uRetAddress;
			}
			else {
				return 0;
			}
		}
		p++;
	}
	return 0;
}

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


/////////////////////////////////////////////////////////////////////////////
//global

ULONG		g_DebugObject;
ULONG		g_ObpAllocateObject;
ULONG		g_ObpIncrementHandleCountEx;
ULONG		g_ObpDecrementHandleCount;
ULONG		g_ObpFreeObject;

ULONG		g_JmpObpAllocateObject;
ULONG		g_JmpObpIncrementHandleCountEx;
ULONG		g_JmpObpDecrementHandleCount;
ULONG		g_JmpObpFreeObject;

BOOLEAN		g_bSuccessHookAllobj;
BOOLEAN		g_bSuccessHookObpInc;
BOOLEAN		g_bSuccessHookObpDec;
BOOLEAN		g_bSuccessHookFreeObj;

UCHAR		g_cAllobjCode[5];
UCHAR		g_cObpIncCode[5];
UCHAR		g_cObpDecCode[5];
UCHAR		g_cFreeObjCode[5];


VOID __declspec(naked) FiliterAllobj()
{
	__asm{
		cmp		esi,g_DebugObject
		jnz		__EXIT
		mov		[edx],0
		__EXIT:
		mov     ecx, [ecx]
		cmp     ecx, [esi + 20h]
		jmp		g_JmpObpAllocateObject
	}
}

VOID __declspec(naked) FiliterObpInc()
{
	__asm
	{
		cmp			edi, g_DebugObject
		jz			__EXIT
		lock xadd	[ecx], eax
		__EXIT:
		inc			eax
		jmp			g_JmpObpIncrementHandleCountEx
	}
}

VOID __declspec(naked) FiliterObpDec()
{
	__asm
	{
		push		esi
		mov			esi,g_DebugObject
		add			esi,0x1c
		cmp			esi,edi
		jz			__EXIT
		lock xadd	[edi], eax
		__EXIT:
		pop			esi
		pop			edi
		jmp			g_JmpObpDecrementHandleCount
	}
}

VOID __declspec(naked) FiliterFreeObj()
{
	__asm
	{
		cmp			eax,g_DebugObject
		jz			__EXIT
		lock xadd	[ecx], edx
		__EXIT:
		test		[esi + 0Fh], 1
		jmp			g_JmpObpFreeObject
	}
}


BOOLEAN AntiCheak(PDRIVER_OBJECT pDriverObj)
{
	PLDR_DATA_TABLE_ENTRY		ldr;
	UCHAR						cDbgObjSignCode[] = {0xff,0x75,0x10,0xff,0x35};
	SIGNATURE_INFO SignCode[4][5] = {
		{{0x14,10},{0x10, 7},{0xf0, 4},{0x1a, 1},{0x8b, 0}},
		{{0xe8,11},{0x33, 6},{0x1c, 2},{0x40, 1},{0xf0, 0}},
		{{0x56,12},{0xe8,11},{0x1c, 4},{0xc8, 2},{0xf0, 0}},
		{{0x40,19},{0xe8,14},{0x18, 4},{0xca, 2},{0xf0, 0}},
	};
	g_DebugObject = GetAddress(KeServiceDescriptorTable.ServiceTableBase[61], cDbgObjSignCode, 1);
	if (!MmIsAddressValid((PVOID)g_DebugObject))
	{
		return 0;
	}
	g_DebugObject = *(ULONG*)g_DebugObject;
	ldr = SearchDriver(pDriverObj, L"ntoskrnl.exe");
	if (ldr==NULL)
	{
		KdPrint(("Ldr null"));
		return FALSE;
	}
	g_ObpAllocateObject = SearchAddressForSign((ULONG)ldr->DllBase, ldr->SizeOfImage, SignCode[0]);
	g_ObpIncrementHandleCountEx = SearchAddressForSign((ULONG)ldr->DllBase, ldr->SizeOfImage, SignCode[1]);
	g_ObpDecrementHandleCount = SearchAddressForSign((ULONG)ldr->DllBase, ldr->SizeOfImage, SignCode[2]);
	g_ObpFreeObject = SearchAddressForSign((ULONG)ldr->DllBase, ldr->SizeOfImage, SignCode[3]);
	if (!(g_ObpAllocateObject&& g_ObpIncrementHandleCountEx&& g_ObpDecrementHandleCount&& g_ObpFreeObject))
	{
		return FALSE;
	}
	g_JmpObpAllocateObject = g_ObpAllocateObject + 0x5;
	g_JmpObpDecrementHandleCount = g_ObpDecrementHandleCount + 0x5;
	g_JmpObpFreeObject = g_ObpFreeObject + 0x8;
	g_JmpObpIncrementHandleCountEx = g_ObpIncrementHandleCountEx + 0x5;
	g_bSuccessHookAllobj = Jmp_HookFunction(g_ObpAllocateObject,(ULONG)FiliterAllobj , g_cAllobjCode);
	g_bSuccessHookFreeObj = Jmp_HookFunction(g_ObpFreeObject, (ULONG)FiliterFreeObj, g_cFreeObjCode);
	g_bSuccessHookObpDec = Jmp_HookFunction(g_ObpDecrementHandleCount, (ULONG)FiliterObpDec, g_cObpDecCode);
	g_bSuccessHookObpInc = Jmp_HookFunction(g_ObpIncrementHandleCountEx, (ULONG)FiliterObpInc, g_cObpIncCode);
	return TRUE;
}


VOID UnAntiCheck()
{
	if (g_bSuccessHookAllobj)
	{
		Res_HookFunction(g_ObpAllocateObject, g_cAllobjCode, 5);
	}
	if (g_bSuccessHookFreeObj)
	{
		Res_HookFunction(g_ObpFreeObject, g_cFreeObjCode, 5);
	}
	if (g_bSuccessHookObpDec)
	{
		Res_HookFunction(g_ObpDecrementHandleCount, g_cObpDecCode, 5);
	}
	if (g_bSuccessHookObpInc)
	{
		Res_HookFunction(g_ObpIncrementHandleCountEx, g_cObpIncCode, 5);
	}
}



/*

00000019	744.33764648	83E435B0
00000020	744.33886719	83E410FC
00000021	744.34002686	83E41F1A
00000022	744.34094238	83E40703

nt!ObpAllocateObject+0x1ca:
83e435a7 897810          mov     dword ptr [eax+10h],edi
83e435aa 8bd1            mov     edx,ecx
83e435ac f00fc11a        lock xadd dword ptr [edx],ebx
83e435b0 8b09            mov     ecx,dword ptr [ecx]                            hook
83e435b2 3b4e20          cmp     ecx,dword ptr [esi+20h]
83e435b5 7603            jbe     nt!ObpAllocateObject+0x1dd (83e435ba)
83e435b7 894e20          mov     dword ptr [esi+20h],ecx
83e435ba 8b4d14          mov     ecx,dword ptr [ebp+14h]


nt!ObpIncrementHandleCountEx+0x435:
83e410ea 8d4140          lea     eax,[ecx+40h]
83e410ed 3900            cmp     dword ptr [eax],eax
83e410ef 7405            je      nt!ObpIncrementHandleCountEx+0x441 (83e410f6)
83e410f1 e8a343e0ff      call    nt!KiCheckForKernelApcDelivery (83c45499)
83e410f6 33c0            xor     eax,eax
83e410f8 8d4f1c          lea     ecx,[edi+1Ch]
83e410fb 40              inc     eax
83e410fc f00fc101        lock xadd dword ptr [ecx],eax


nt!ObpDecrementHandleCount+0x145:
83e41f09 e82b24e7ff      call    nt!KeUnstackDetachProcess (83cb4339)
83e41f0e 56              push    esi
83e41f0f e851f2ffff      call    nt!ObpDeleteNameCheck (83e41165)
83e41f14 83c71c          add     edi,1Ch
83e41f17 83c8ff          or      eax,0FFFFFFFFh
83e41f1a f00fc107        lock xadd dword ptr [edi],eax
83e41f1e 5f              pop     edi
83e41f1f 5b              pop     ebx


nt!ObpFreeObject+0x15e:
83e40700 83caff          or      edx,0FFFFFFFFh
83e40703 f00fc111        lock xadd dword ptr [ecx],edx
83e40707 f6460f01        test    byte ptr [esi+0Fh],1
83e4070b 746e            je      nt!ObpFreeObject+0x1d9 (83e4077b)
83e4070d 8b4610          mov     eax,dword ptr [esi+10h]
83e40710 85c0            test    eax,eax
83e40712 0f84a1000000    je      nt!ObpFreeObject+0x217 (83e407b9)
83e40718 8b4818          mov     ecx,dword ptr [eax+18h]

*/