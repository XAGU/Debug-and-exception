#include <ntifs.h>
#include <ntimage.h>

#define HANDLE_VALUE_INC 4 // Amount to increment the Value to get to the next handle

typedef struct _HANDLE_TABLE {

	//
	//  A pointer to the top level handle table tree node.
	//

	ULONG_PTR TableCode;

	//
	//  The process who is being charged quota for this handle table and a
	//  unique process id to use in our callbacks
	//

	struct _EPROCESS *QuotaProcess;
	HANDLE UniqueProcessId;


	//
	// These locks are used for table expansion and preventing the A-B-A problem
	// on handle allocate.
	//

#define HANDLE_TABLE_LOCKS 4

	EX_PUSH_LOCK HandleTableLock[HANDLE_TABLE_LOCKS];

	//
	//  The list of global handle tables.  This field is protected by a global
	//  lock.
	//

	LIST_ENTRY HandleTableList;

	//
	// Define a field to block on if a handle is found locked.
	//
	EX_PUSH_LOCK HandleContentionEvent;

	//
	// Debug info. Only allocated if we are debugging handles
	//
	ULONG DebugInfo;

	//
	//  The number of pages for additional info.
	//  This counter is used to improve the performance
	//  in ExGetHandleInfo
	//
	LONG ExtraInfoPages;

	//
	//  This is a singly linked list of free table entries.  We don't actually
	//  use pointers, but have each store the index of the next free entry
	//  in the list.  The list is managed as a lifo list.  We also keep track
	//  of the next index that we have to allocate pool to hold.
	//

	ULONG FirstFree;

	//
	// We free handles to this list when handle debugging is on or if we see
	// that a thread has this handles bucket lock held. The allows us to delay reuse
	// of handles to get a better chance of catching offenders
	//

	ULONG LastFree;

	//
	// This is the next handle index needing a pool allocation. Its also used as a bound
	// for good handles.
	//

	ULONG NextHandleNeedingPool;

	//
	//  The number of handle table entries in use.
	//

	LONG HandleCount;

	//
	// Define a flags field
	//
	union {
		ULONG Flags;

		//
		// For optimization we reuse handle values quickly. This can be a problem for
		// some usages of handles and makes debugging a little harder. If this
		// bit is set then we always use FIFO handle allocation.
		//
		BOOLEAN StrictFIFO : 1;
	};

} HANDLE_TABLE, *PHANDLE_TABLE;

typedef struct _HANDLE_TABLE_ENTRY {

	//
	//  The pointer to the object overloaded with three ob attributes bits in
	//  the lower order and the high bit to denote locked or unlocked entries
	//

	union {

		PVOID Object;

		ULONG ObAttributes;

		ULONG InfoTable;

		ULONG_PTR Value;
	};

	//
	//  This field either contains the granted access mask for the handle or an
	//  ob variation that also stores the same information.  Or in the case of
	//  a free entry the field stores the index for the next free entry in the
	//  free list.  This is like a FAT chain, and is used instead of pointers
	//  to make table duplication easier, because the entries can just be
	//  copied without needing to modify pointers.
	//

	union {

		union {

			ACCESS_MASK GrantedAccess;

			struct {

				USHORT GrantedAccessIndex;
				USHORT CreatorBackTraceIndex;
			};
		};

		LONG NextFreeTableEntry;
	};

} HANDLE_TABLE_ENTRY, *PHANDLE_TABLE_ENTRY;

typedef BOOLEAN(*EX_ENUMERATE_HANDLE_ROUTINE)(
	IN PHANDLE_TABLE_ENTRY HandleTableEntry,
	IN HANDLE Handle,
	IN PVOID EnumParameter
	);

typedef NTKERNELAPI BOOLEAN (*EXENUMHANDLETABLE)(
	__in PHANDLE_TABLE HandleTable,											//Ŀ����̾����
	__in EX_ENUMERATE_HANDLE_ROUTINE EnumHandleProcedure,					//�ص�����
	__in PVOID EnumParameter,
	__out_opt PHANDLE Handle
);

PHANDLE_TABLE_ENTRY
ExpLookupHandleTableEntry(
	IN PHANDLE_TABLE HandleTable,
	IN ULONG Handle
)
{
	// һ��Ѿֲ�����
	ULONG_PTR i, j, k;
	ULONG_PTR CapturedTable;
	ULONG TableLevel;
	PHANDLE_TABLE_ENTRY Entry = NULL;

	PUCHAR TableLevel1;
	PUCHAR TableLevel2;
	PUCHAR TableLevel3;

	ULONG_PTR MaxHandle;

	PAGED_CODE();

	MaxHandle = *(volatile ULONG *)&HandleTable->NextHandleNeedingPool;

	// �жϵ�ǰ����Ƿ���Ч
	if (Handle >= MaxHandle) {
		return NULL;
	}

	//
	// �õ���ǰ�������ȼ� -- �� CapturedTable �����2λ
	// �� (CapturedTable - TableLevel) �������3������ʼ��ַ��
	// ͨ��Handle.Value�еĺ�30λ����������ţ��ҵ�����ID��Ӧ��HANDLE_TABLE_ENTRY
	//
	CapturedTable = *(volatile ULONG_PTR *)&HandleTable->TableCode;
	TableLevel = (ULONG)(CapturedTable & 3);
	CapturedTable -= TableLevel;

	// ��3�����: 0��1��2
	switch (TableLevel) {

	case 0:

		TableLevel1 = (PUCHAR)CapturedTable;

		// ��һ��������б���ľ���һ��HANDLE_TABLE_ENTRY
		// ������*2 �õ������е�ƫ����
		Entry = (PHANDLE_TABLE_ENTRY)&TableLevel1[Handle * 2];

		break;

	case 1:

		TableLevel2 = (PUCHAR)CapturedTable;

		// ��2����ϲ� �� �²� [�в�Ϊ��]
		// ��2KB�����i����������²���е�����
		i = Handle % (2 * 1024);

		// �ϲ㿪ʼ��ƫ��j��ָ������²�Ŀ�ʼ��
		Handle -= i;
		j = Handle / ((2 * 1024) / 8);

		TableLevel1 = (PUCHAR) *(PHANDLE_TABLE_ENTRY *)&TableLevel2[j];
		Entry = (PHANDLE_TABLE_ENTRY)&TableLevel1[i * 2];

		break;

	case 2:

		TableLevel3 = (PUCHAR)CapturedTable;

		i = Handle % (2 * 1024);

		Handle -= i;

		k = Handle / ((2 * 1024) / 8);

		j = k % (4 * 1024);

		k -= j;

		k = k / (1024 / 2);


		TableLevel2 = (PUCHAR) *(PHANDLE_TABLE_ENTRY *)&TableLevel3[k];
		TableLevel1 = (PUCHAR) *(PHANDLE_TABLE_ENTRY *)&TableLevel2[j];
		Entry = (PHANDLE_TABLE_ENTRY)&TableLevel1[i * 2];

		break;

	default:
		_assume(0);
	}

	return Entry;
}

//////////////////////////////////////////////////////////////////////////////////////////////
//global
EXENUMHANDLETABLE			ExEnumHandleTable;

PVOID GetExportFunAddress(wchar_t *FunName)
{
	UNICODE_STRING		usFunName;
	RtlInitUnicodeString(&usFunName, FunName);
	return MmGetSystemRoutineAddress(&usFunName);
}

BOOLEAN EnumCallBack(
	IN PHANDLE_TABLE_ENTRY HandleTableEntry,
	IN HANDLE Handle,
	IN PVOID EnumParameter
	)
{
	KdPrint(("<-->%X---%X", HandleTableEntry,HandleTableEntry->Object));
	return FALSE;
}


VOID MyEnumHandleTable()
{
	NTSTATUS		Status;
	ULONG			Process;
	ULONG			Handle;
	PHANDLE_TABLE_ENTRY	pHandleTabEntry;
	ExEnumHandleTable = (EXENUMHANDLETABLE)GetExportFunAddress(L"ExEnumHandleTable");
	if (ExEnumHandleTable == 0)
	{
		KdPrint(("<-->GetExportFunAddress Failed !"));
		return;
	}
	Status = PsLookupProcessByProcessId((HANDLE)560, (PEPROCESS*)&Process);
	if (!NT_SUCCESS(Status))
	{
		return;
	}

	for (Handle = 0; (pHandleTabEntry = ExpLookupHandleTableEntry(*(PHANDLE_TABLE*)(Process + 0xF4),Handle))!=NULL; Handle+=HANDLE_VALUE_INC)
	{
		KdPrint(("%d", Handle));
		KdPrint(("<-->%X  %X", pHandleTabEntry, pHandleTabEntry->Object));
	}

	ObDereferenceObject((PVOID)Process);
}

VOID EnumHandleTable()
{
	NTSTATUS		Status;
	ULONG			Process;
	HANDLE			Handle;
	ExEnumHandleTable = (EXENUMHANDLETABLE)GetExportFunAddress(L"ExEnumHandleTable");
	if (ExEnumHandleTable == 0)
	{
		KdPrint(("<-->GetExportFunAddress Failed !"));
		return;
	}
	Status = PsLookupProcessByProcessId((HANDLE)560, (PEPROCESS*)&Process);
	if (!NT_SUCCESS(Status))
	{
		return;
	}

	ExEnumHandleTable(*(PHANDLE_TABLE*)(Process + 0xF4), EnumCallBack, NULL, &Handle);

	ObDereferenceObject((PVOID)Process);
}

VOID DriverUnLoad(PDRIVER_OBJECT pDriverObj)
{
	KdPrint(("<-->����ж�سɹ���"));
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObj, PUNICODE_STRING usRegPath)
{
	KdPrint(("<-->�������سɹ���"));
	//EnumHandleTable();
	MyEnumHandleTable();
	pDriverObj->DriverUnload = DriverUnLoad;
	return STATUS_SUCCESS;
}