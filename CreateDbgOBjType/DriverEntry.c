#include <ntifs.h>
#include <ntimage.h>

#define __Max(a,b) a>b?a:b
#define SystemModuleInformationClass	11
//
// Define debug object access types. No security is present on this object.
//
#define DEBUG_READ_EVENT        (0x0001)
#define DEBUG_PROCESS_ASSIGN    (0x0002)
#define DEBUG_SET_INFORMATION   (0x0004)
#define DEBUG_QUERY_INFORMATION (0x0008)
#define DEBUG_ALL_ACCESS     (STANDARD_RIGHTS_REQUIRED|SYNCHRONIZE|DEBUG_READ_EVENT|DEBUG_PROCESS_ASSIGN|\
                              DEBUG_SET_INFORMATION|DEBUG_QUERY_INFORMATION)

#define DEBUG_KILL_ON_CLOSE  (0x1) // Kill all debuggees on last handle close


#pragma pack(1)
typedef struct ServiceDescriptorEntry {
	unsigned int *ServiceTableBase;
	unsigned int *ServiceCounterTableBase; //仅适用于checked build版本
	unsigned int NumberOfServices;
	unsigned char *ParamTableBase;
} ServiceDescriptorTableEntry_t, *PServiceDescriptorTableEntry_t;
#pragma pack()

__declspec(dllimport) ServiceDescriptorTableEntry_t KeServiceDescriptorTable;

typedef struct
{
	PVOID section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT PathLength;
	char ImageName[MAXIMUM_FILENAME_LENGTH];

}SYSTEM_MODULE, *PSYSTEM_MODULE;

typedef struct
{
	ULONG ModuleCount;
	SYSTEM_MODULE Module[0];
}SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

typedef NTKERNELAPI NTSTATUS (*OBCREATEOBJECTTYPE)(
	__in PUNICODE_STRING TypeName,
	__in UCHAR* ObjectTypeInitializer,
	__in_opt PSECURITY_DESCRIPTOR SecurityDescriptor,
	__out POBJECT_TYPE *ObjectType
);

typedef NTSTATUS
(*ZWQUERYSYSTEMINFORMATION)(
	ULONG SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength OPTIONAL
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

NTSTATUS GetModuleByName(char *szModuleName, PSYSTEM_MODULE ImageInfo)
{
	NTSTATUS	status;
	UNICODE_STRING	usQueryFunc;

	ULONG count;
	ULONG BufferSize = 0;
	PSYSTEM_MODULE_INFORMATION pSystemModuleInformation = NULL;
	PSYSTEM_MODULE pSystemModule = NULL;

	ZWQUERYSYSTEMINFORMATION	ZwQuerySystemInformation = NULL;

	status = STATUS_UNSUCCESSFUL;

	RtlInitUnicodeString(&usQueryFunc, L"ZwQuerySystemInformation");
	ZwQuerySystemInformation = (ZWQUERYSYSTEMINFORMATION)MmGetSystemRoutineAddress(&usQueryFunc);
	if (ZwQuerySystemInformation == NULL)
	{
		return status;
	}

	status = ZwQuerySystemInformation(SystemModuleInformationClass, NULL, 0, &BufferSize);
	if (status != STATUS_INFO_LENGTH_MISMATCH)
	{
		return status;
	}

	pSystemModuleInformation = (PSYSTEM_MODULE_INFORMATION)ExAllocatePool(NonPagedPool, BufferSize);
	if (pSystemModuleInformation == NULL)
	{
		return STATUS_UNSUCCESSFUL;
	}

	status = ZwQuerySystemInformation(SystemModuleInformationClass, pSystemModuleInformation, BufferSize, &BufferSize);
	if (!NT_SUCCESS(status))
	{
		ExFreePool(pSystemModuleInformation);
		return status;
	}

	status = STATUS_UNSUCCESSFUL;
	pSystemModule = pSystemModuleInformation->Module;
	for (count = 0; count < pSystemModuleInformation->ModuleCount; count++)
	{
		//if (strstr(_strupr(&pSystemModule[count].ImageName), _strupr(szModuleName)) != 0)
		if (strstr(pSystemModule[count].ImageName, szModuleName) != 0)
		{
			__try {
				*ImageInfo = pSystemModule[count];
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {
				break;
			}

			status = STATUS_SUCCESS;
			break;
		}
	}

	ExFreePool(pSystemModuleInformation);
	return status;
}

//基址重定位
VOID ReLocMoudle(PVOID pNewImage, PVOID pOrigImage, ULONG Value, ULONG* Vector,ULONG VecLen)
{
	ULONG					Index;
	ULONG_PTR				uIndex;
	ULONG_PTR				uRelocTableSize;
	USHORT					TypeValue;
	USHORT					*pwOffsetArrayAddress;
	ULONG_PTR				uTypeOffsetArraySize;
	ULONG_PTR				uRelocOffset;
	ULONG_PTR				uRelocAddress;
	IMAGE_DATA_DIRECTORY	ImageDataDirectory;
	PIMAGE_DOS_HEADER		pImageDosHeader;
	PIMAGE_NT_HEADERS		pImageNtHeaders;
	IMAGE_BASE_RELOCATION	*pImageBaseRelocation;
	pImageDosHeader = (PIMAGE_DOS_HEADER)pNewImage;
	pImageNtHeaders = (PIMAGE_NT_HEADERS)((ULONG_PTR)pNewImage + pImageDosHeader->e_lfanew);

	uRelocOffset = (ULONG_PTR)pOrigImage - pImageNtHeaders->OptionalHeader.ImageBase;

	ImageDataDirectory = pImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	pImageBaseRelocation = (PIMAGE_BASE_RELOCATION)(ImageDataDirectory.VirtualAddress + (ULONG_PTR)pNewImage);
	uRelocTableSize = ImageDataDirectory.Size;
	Index = 0;
	while (uRelocTableSize)
	{
		uTypeOffsetArraySize = (pImageBaseRelocation->SizeOfBlock -
			sizeof(ULONG_PTR) * 2) / sizeof(USHORT);
		pwOffsetArrayAddress = pImageBaseRelocation->TypeOffset;
		for (uIndex = 0; uIndex < uTypeOffsetArraySize; uIndex++)
		{
			TypeValue = pwOffsetArrayAddress[uIndex];
			if (TypeValue >> 12 == IMAGE_REL_BASED_HIGHLOW)
			{
				uRelocAddress = (TypeValue & 0xfff) + pImageBaseRelocation->VirtualAddress + (ULONG_PTR)pNewImage;
				if (!MmIsAddressValid((PVOID)uRelocAddress))
				{
					continue;
				}
				*(PULONG_PTR)uRelocAddress += uRelocOffset;
				if (Index < VecLen)
				{
					if (*(ULONG*)uRelocAddress == Value)
					{
						Vector[Index] = uRelocAddress-((ULONG)pNewImage - (ULONG)pOrigImage);
						Index++;
					}
				}
			}
		}
		uRelocTableSize -= pImageBaseRelocation->SizeOfBlock;
		pImageBaseRelocation = (IMAGE_BASE_RELOCATION*)((ULONG_PTR)pImageBaseRelocation + pImageBaseRelocation->SizeOfBlock);
	}
}

NTSTATUS GetValuePointer(wchar_t *strFileName, PVOID pOrigImage,ULONG Value,ULONG* Vector,ULONG VecLen)
{
	NTSTATUS				status;
	HANDLE					hFile;
	LARGE_INTEGER			FileOffset;
	UNICODE_STRING			usFileName;
	OBJECT_ATTRIBUTES		ObjAttr;
	IO_STATUS_BLOCK			ioStatusBlock;
	IMAGE_DOS_HEADER		ImageDosHeader;
	IMAGE_NT_HEADERS		ImageNtHeaders;
	IMAGE_SECTION_HEADER	*pImageSectionHeader;
	ULONG_PTR				uIndex;
	PVOID					lpVirtualPointer;
	ULONG_PTR				SecVirtualAddress, SizeOfSection;
	ULONG_PTR				PointerToRawData;
	if (!MmIsAddressValid(strFileName))
	{
		return STATUS_UNSUCCESSFUL;
	}
	RtlInitUnicodeString(&usFileName, strFileName);
	InitializeObjectAttributes(&ObjAttr,
		&usFileName,
		OBJ_CASE_INSENSITIVE,
		NULL,
		NULL);

	status = ZwCreateFile(&hFile,
		FILE_ALL_ACCESS,
		&ObjAttr,
		&ioStatusBlock,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ,
		FILE_OPEN,
		FILE_NON_DIRECTORY_FILE,
		NULL,
		0);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("ZwCreateFile Fail:%X", status));
		return status;
	}
	FileOffset.QuadPart = 0;
	status = ZwReadFile(hFile,
		NULL,
		NULL,
		NULL,
		&ioStatusBlock,
		&ImageDosHeader,
		sizeof(IMAGE_DOS_HEADER),
		&FileOffset,
		NULL);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("Read ImageDosHeader Fail:%X", status));
		ZwClose(hFile);
		return status;
	}
	FileOffset.QuadPart = ImageDosHeader.e_lfanew;
	status = ZwReadFile(hFile,
		NULL,
		NULL,
		NULL,
		&ioStatusBlock,
		&ImageNtHeaders,
		sizeof(IMAGE_NT_HEADERS),
		&FileOffset,
		NULL);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("Read IMAGE_NT_HEADERS Fail:%X", status));
		ZwClose(hFile);
		return status;
	}
	pImageSectionHeader = ExAllocatePool(NonPagedPool, sizeof(IMAGE_SECTION_HEADER)*ImageNtHeaders.FileHeader.NumberOfSections);
	if (pImageSectionHeader == 0)
	{
		KdPrint(("Allocate ImageSectionHeader Fail:%X", status));
		ZwClose(hFile);
		return status;
	}
	FileOffset.QuadPart += sizeof(IMAGE_NT_HEADERS);
	status = ZwReadFile(hFile,
		NULL,
		NULL,
		NULL,
		&ioStatusBlock,
		pImageSectionHeader,
		sizeof(IMAGE_SECTION_HEADER)*ImageNtHeaders.FileHeader.NumberOfSections,
		&FileOffset,
		NULL);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("Read pImageSectionHeader Fail:%X", status));
		ExFreePool(pImageSectionHeader);
		ZwClose(hFile);
		return status;
	}
	lpVirtualPointer = ExAllocatePool(NonPagedPool, ImageNtHeaders.OptionalHeader.SizeOfImage);
	if (lpVirtualPointer == 0)
	{
		KdPrint(("Allocate lpVirtualPointer is null"));
		ExFreePool(pImageSectionHeader);
		ZwClose(hFile);
		return status;
	}
	RtlZeroMemory(lpVirtualPointer, ImageNtHeaders.OptionalHeader.SizeOfImage);
	RtlCopyMemory(lpVirtualPointer,
		&ImageDosHeader,
		sizeof(IMAGE_DOS_HEADER));
	RtlCopyMemory((PVOID)((ULONG_PTR)lpVirtualPointer + ImageDosHeader.e_lfanew),
		&ImageNtHeaders,
		sizeof(IMAGE_NT_HEADERS));
	RtlCopyMemory((PVOID)((ULONG_PTR)lpVirtualPointer + ImageDosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS)),
		pImageSectionHeader,
		sizeof(IMAGE_SECTION_HEADER)*ImageNtHeaders.FileHeader.NumberOfSections);
	for (uIndex = 0; uIndex < ImageNtHeaders.FileHeader.NumberOfSections; uIndex++)
	{
		SecVirtualAddress = pImageSectionHeader[uIndex].VirtualAddress;
		SizeOfSection = __Max(pImageSectionHeader[uIndex].SizeOfRawData,
			pImageSectionHeader[uIndex].Misc.VirtualSize);
		PointerToRawData = pImageSectionHeader[uIndex].PointerToRawData;
		FileOffset.QuadPart = PointerToRawData;
		status = ZwReadFile(hFile,
			NULL,
			NULL,
			NULL,
			&ioStatusBlock,
			(PVOID)((ULONG_PTR)lpVirtualPointer + SecVirtualAddress),
			SizeOfSection,
			&FileOffset,
			NULL);
		if (!NT_SUCCESS(status))
		{
			KdPrint(("Read Fail is pImageSectionHeader[%d]", uIndex));
			ExFreePool(pImageSectionHeader);
			ExFreePool(lpVirtualPointer);
			ZwClose(hFile);
			return status;
		}
	}
	ReLocMoudle(lpVirtualPointer, pOrigImage, Value, Vector,VecLen);
	KdPrint(("ok!"));
	ExFreePool(pImageSectionHeader);
	ExFreePool(lpVirtualPointer);
	ZwClose(hFile);
	return STATUS_SUCCESS;
}

VOID CreateDebugObjectType()
{
	ULONG					Index;
	NTSTATUS				status;
	ULONG					DebugObjectType;
	UCHAR					ObjectTypeInit[0x50];
	OBCREATEOBJECTTYPE		fnObCreateObjectType;
	SYSTEM_MODULE			ImageInfo;
	UNICODE_STRING			usFunName;
	UNICODE_STRING			usTypeName;

	ANSI_STRING				asMapImagePath;
	UNICODE_STRING			usMapImagePath;

	ULONG					Vector[20];

	POBJECT_TYPE			pDbgkNewDebugObjectType = NULL;
	UCHAR					cDbgObjSignCode[] = { 0xff,0x75,0x10,0xff,0x35 };
	 
	memset(Vector, 0, sizeof(ULONG)*20);

	RtlInitUnicodeString(&usFunName, L"ObCreateObjectType");
	RtlInitUnicodeString(&usTypeName, L"xagu");

	if (!NT_SUCCESS(GetModuleByName("ntoskrnl.exe",&ImageInfo))&&
		!NT_SUCCESS(GetModuleByName("ntkrnlpa.exe", &ImageInfo)))
	{
		return;
	}
	KdPrint(("%s", ImageInfo.ImageName));
	RtlInitAnsiString(&asMapImagePath, ImageInfo.ImageName);
	RtlAnsiStringToUnicodeString(&usMapImagePath, &asMapImagePath, TRUE);
	///////////////////////////////////////////////////////////////////////
	//得到ObCreateObjectType地址
	fnObCreateObjectType = (OBCREATEOBJECTTYPE)MmGetSystemRoutineAddress(&usFunName);
	KdPrint(("%X", MmGetSystemRoutineAddress(&usFunName)));
	if (!fnObCreateObjectType)
	{
		KdPrint(("MmGetSystemRoutineAddress:fnObCreateObjectType"));
		return;
	}
	//通过特征码取DebugObject
	DebugObjectType = GetAddress(KeServiceDescriptorTable.ServiceTableBase[61], cDbgObjSignCode, 1);
	if (!MmIsAddressValid((PVOID)DebugObjectType))
	{
		KdPrint(("GetAddress"));
		return ;
	}
	status = GetValuePointer(usMapImagePath.Buffer, ImageInfo.ImageBase, DebugObjectType, Vector,20);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("GetValuePointer"));
		return;
	}

	DebugObjectType = *(ULONG*)DebugObjectType;

	RtlCopyMemory(ObjectTypeInit, (PVOID)(DebugObjectType + 0x28), 0x50);
	*(ULONG*)(ObjectTypeInit + 0x1c) = DEBUG_ALL_ACCESS;

	status = fnObCreateObjectType(&usTypeName, ObjectTypeInit, NULL, &pDbgkNewDebugObjectType);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("fnObCreateObjectType"));
		return;
	}

	PageProtectOff();

	for (Index = 0; Index < 20; Index++)
	{
		if (MmIsAddressValid((PVOID)Vector[Index]))
		{
			*(ULONG*)(Vector[Index]) = (ULONG)(pDbgkNewDebugObjectType);
		}
		KdPrint(("%d------%X", Index, Vector[Index]));
	}

	PageProtectOn();
}

VOID DriverUnLoad(PDRIVER_OBJECT pDrverObject)
{
	KdPrint(("驱动卸载成功！"));
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDrverObject, PUNICODE_STRING usRegPath)
{

	KdPrint(("驱动加载成功！"));
	CreateDebugObjectType();
	pDrverObject->DriverUnload = DriverUnLoad;
	return STATUS_SUCCESS;
}
