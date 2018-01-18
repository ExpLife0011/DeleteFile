#include <ntifs.h>
#include <ntddk.h>

#define KERNEL_TAG 0x80000000

typedef struct _HANDLE_TABLE_ENTRY {
	union {
		PVOID Object;
		ULONG ObAttributes;
	};
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

BOOLEAN CompareObjectName(PVOID Object, PUNICODE_STRING FileName)
{
	PUNICODE_STRING CompletePath = NULL;

	ULONG PathLength;

	NTSTATUS status;

	BOOLEAN Ret;

	if (MmIsAddressValid(Object) && Object != NULL)
	{
		status = ObQueryNameString(Object, NULL, 0, &PathLength);

		if (status == STATUS_INFO_LENGTH_MISMATCH)
		{
			CompletePath = (PUNICODE_STRING)ExAllocatePoolWithTag(NonPagedPool, PathLength, 'ytz');

			if (CompletePath != NULL)
			{
				status = ObQueryNameString(Object, (POBJECT_NAME_INFORMATION)CompletePath, PathLength, &PathLength);

				if (NT_SUCCESS(status))
				{
					Ret = (BOOLEAN)RtlCompareUnicodeString(CompletePath, FileName, TRUE);
					Ret = !Ret;
					ExFreePoolWithTag(CompletePath, 'ytz');
					return Ret;
				}
			}
			else
			{
				KdPrint(("Allocate Memory Error!\n"));
				return FALSE;
			}
		}
		else
		{
			KdPrint(("SomeThing Wrong!\n"));
			return FALSE;
		}
	}
	else
	{
		KdPrint(("Valid Memory!\n"));
		return FALSE;
	}
	return FALSE;
}

VOID Unload(PDRIVER_OBJECT DriverObject)
{
	KdPrint(("Unload Success!\n"));
}

VOID SearchCurrentProcessHandleTable(PEPROCESS CurrentProcess, PUNICODE_STRING FileName)
{
	ULONG *FirstLayer;													//用来循环句柄表的第一层
	ULONG *SecondLayer;													//用来循环的句柄表的第二次（希望这个变量用不上），用了则证明当前的进程线程数目超过了512*1024
	ULONG TableCode;													//HANDLE_TABLE的TableCode，决定了HANDLE_TABLE_ENTRY的地址
	PHANDLE_TABLE_ENTRY TempEntry;										//作为一个临时变量来处理所有的HANDLE_TABLE_ENTRY
	ULONG i;															//用来循环查找HANDLE_TABLE_ENTRY的下标变量
	ULONG TempObject;													//一个临时变量，用来保存HANDLE_TABLE_ENTRY中的OBJECT的值
	ULONG j;															//作为一个临时变量来遍历第二层的数组
	ULONG t = 0;														//t作为他在句柄表中的位置，t *4就是句柄的值
	ULONG tHandle;
	KAPC_STATE  Apc;													//用来挂靠使用的

	TableCode = *(ULONG*)((ULONG)CurrentProcess + 0xf4);						//现在的TableCode实际是ObjectTable
	TableCode = *(ULONG*)TableCode;												//现在TableCode才是TableCode

	if (TableCode & 1)															//代表一共有两层句柄表，第一层指向一个4k的页面，有1024个数组，每个数组指向一个4k的页面，每个页面保存512个HandleTableEntry
	{
		TableCode = TableCode & 0xFFFFFFF4;										//虽然这里是1，清空最低位就可以了，但是为了统一性，这里依然写清空末两位
		FirstLayer = (ULONG*)TableCode;
		while (*FirstLayer)														//并不是当前页面上的1024个数组每一个元素都有值，因此找到一个为0的地方为止就可以了
		{
			TempEntry = (PHANDLE_TABLE_ENTRY)(*FirstLayer);
			for (i = 0; i < 512; ++i, ++TempEntry, ++t)
			{
				if (TempEntry->Object == NULL)
					continue;
				TempObject = (ULONG)TempEntry->Object;
				TempObject = TempObject & 0xFFFFFFF8;							//低三位是信息位，保存着信息变量，因此这里要清空掉

				if (*(UCHAR*)(TempObject + 0xc) == 28)							//先判断是不是当前的Object是不是文件(OBJECT_HEADER里面的TypeIndex)
				{
					TempObject += 0x18;											//得到对象本身
					if (CompareObjectName((PVOID)TempObject, FileName))			//比较对象是否是我们要找的
					{
						if (CurrentProcess == PsGetCurrentProcess())			//如果当前的进程就是当前的进程那就不需要挂靠过去，否则需要挂靠过去
						{
							KdPrint(("ObjectAddress :%x\n", (ULONG)TempObject));
							tHandle = t * 4;
							tHandle |= KERNEL_TAG;
							KdPrint(("t = %x\n", tHandle));
							ZwClose((HANDLE)tHandle);
						}
						else
						{
							KeStackAttachProcess((PKPROCESS)CurrentProcess, &Apc);
							KdPrint(("ObjectAddress :%x\n", (ULONG)TempObject));
							tHandle = t * 4;
							tHandle |= KERNEL_TAG;
							KdPrint(("t = %x\n", tHandle));
							ZwClose((HANDLE)tHandle);
							KeUnstackDetachProcess(&Apc);
						}
					}									
				}
			}
			++FirstLayer;
		}
	}
	else if (TableCode & 2)													//代表一共有三层句柄表，第一层指向一个4k的页面，有1024个数组，每个数组指向一个4k的页面，每个页面有1024个数组，每个数组指向一个4k的页面，每个页面保存512个HandleTableEntry
	{
		TableCode = TableCode & 0xFFFFFFF4;									//虽然这里是1，清空最低位就可以了，但是为了统一性，这里依然写清空末两位
		FirstLayer = (ULONG*)TableCode;
		while (*FirstLayer)													//并不是当前页面上的1024个数组每一个元素都有值，因此找到一个为0的地方为止就可以了
		{
			SecondLayer = (ULONG*)(*FirstLayer);
			for (j = 0; j < 1024; ++j)
			{
				TempEntry = (PHANDLE_TABLE_ENTRY)(*SecondLayer);
				for (i = 0; i < 512; ++i, ++TempEntry, ++t)
				{
					if (TempEntry->Object == NULL)
						continue;
					TempObject = (ULONG)TempEntry->Object;
					TempObject = TempObject & 0xFFFFFFF8;							//低三位是信息位，保存着信息变量，因此这里要清空掉
					if (*(UCHAR*)(TempObject + 0xc) == 28)							//先判断是不是当前的Object是不是文件 
					{
						TempObject += 0x18;											//得到对象本身
						if (CompareObjectName((PVOID)TempObject, FileName))			//比较对象是否是我们要找的
						{
							KdPrint(("%u,ObjectAddress :%x\n", t, (ULONG)TempObject));
							tHandle = t * 4;
							tHandle |= KERNEL_TAG;
							KdPrint(("t = %x\n", tHandle));
							ZwClose((HANDLE)tHandle);
						}
					}
				}
			}
			++FirstLayer;
		}
	}
	else																	//代表只有一层句柄表，指向一个4k的页面，有512个HandleTableEntry
	{
		TempEntry = (PHANDLE_TABLE_ENTRY)TableCode;
		for (i = 0; i < 512; ++i, ++TempEntry, ++t)
		{
			if (TempEntry->Object == NULL)
				continue;
			TempObject = (ULONG)TempEntry->Object;
			TempObject = TempObject & 0xFFFFFFF8;							//低三位是信息位，保存着信息变量，因此这里要清空掉
			if (*(UCHAR*)(TempObject + 0xc) == 28)							//先判断是不是当前的Object是不是文件 
			{
				TempObject += 0x18;											//得到对象本身
				if (CompareObjectName((PVOID)TempObject, FileName))			//比较对象是否是我们要找的
				{
					KdPrint(("%u,ObjectAddress :%x\n", t, (ULONG)TempObject));
					tHandle = t * 4;
					tHandle |= KERNEL_TAG;
					KdPrint(("t = %x\n", tHandle));
					ZwClose((HANDLE)tHandle);
				}
			}
		}
	}
}

VOID SearchAllProcess(PUNICODE_STRING FileName)
{
	PLIST_ENTRY ProcessList;

	PLIST_ENTRY TempList;

	PEPROCESS Eprocess = PsGetCurrentProcess();

	ProcessList = (PLIST_ENTRY)((char *)Eprocess + 0xb8);

	TempList = ProcessList;

	do
	{
		if (*(ULONG*)((ULONG)TempList + 0x3c) != 0)					//判断，如果句柄表存在（如果不是死进程）
			SearchCurrentProcessHandleTable((PEPROCESS)((ULONG)TempList - 0xb8), FileName);
		TempList = TempList->Flink;
	} while (TempList != ProcessList);
}

VOID DeleteFile(LPWSTR File)
{
	UNICODE_STRING FileName;
	RtlInitUnicodeString(&FileName, File);
	SearchAllProcess(&FileName);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegString)
{
	KdPrint(("Entry Driver!\n"));
	DeleteFile(L"\\Device\\HarddiskVolume1\\Users\\Administrator\\Desktop\\a.txt");
	DriverObject->DriverUnload = Unload;
	return STATUS_SUCCESS;
}