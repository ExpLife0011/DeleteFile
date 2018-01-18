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
	ULONG *FirstLayer;													//����ѭ�������ĵ�һ��
	ULONG *SecondLayer;													//����ѭ���ľ����ĵڶ��Σ�ϣ����������ò��ϣ���������֤����ǰ�Ľ����߳���Ŀ������512*1024
	ULONG TableCode;													//HANDLE_TABLE��TableCode��������HANDLE_TABLE_ENTRY�ĵ�ַ
	PHANDLE_TABLE_ENTRY TempEntry;										//��Ϊһ����ʱ�������������е�HANDLE_TABLE_ENTRY
	ULONG i;															//����ѭ������HANDLE_TABLE_ENTRY���±����
	ULONG TempObject;													//һ����ʱ��������������HANDLE_TABLE_ENTRY�е�OBJECT��ֵ
	ULONG j;															//��Ϊһ����ʱ�����������ڶ��������
	ULONG t = 0;														//t��Ϊ���ھ�����е�λ�ã�t *4���Ǿ����ֵ
	ULONG tHandle;
	KAPC_STATE  Apc;													//�����ҿ�ʹ�õ�

	TableCode = *(ULONG*)((ULONG)CurrentProcess + 0xf4);						//���ڵ�TableCodeʵ����ObjectTable
	TableCode = *(ULONG*)TableCode;												//����TableCode����TableCode

	if (TableCode & 1)															//����һ��������������һ��ָ��һ��4k��ҳ�棬��1024�����飬ÿ������ָ��һ��4k��ҳ�棬ÿ��ҳ�汣��512��HandleTableEntry
	{
		TableCode = TableCode & 0xFFFFFFF4;										//��Ȼ������1��������λ�Ϳ����ˣ�����Ϊ��ͳһ�ԣ�������Ȼд���ĩ��λ
		FirstLayer = (ULONG*)TableCode;
		while (*FirstLayer)														//�����ǵ�ǰҳ���ϵ�1024������ÿһ��Ԫ�ض���ֵ������ҵ�һ��Ϊ0�ĵط�Ϊֹ�Ϳ�����
		{
			TempEntry = (PHANDLE_TABLE_ENTRY)(*FirstLayer);
			for (i = 0; i < 512; ++i, ++TempEntry, ++t)
			{
				if (TempEntry->Object == NULL)
					continue;
				TempObject = (ULONG)TempEntry->Object;
				TempObject = TempObject & 0xFFFFFFF8;							//����λ����Ϣλ����������Ϣ�������������Ҫ��յ�

				if (*(UCHAR*)(TempObject + 0xc) == 28)							//���ж��ǲ��ǵ�ǰ��Object�ǲ����ļ�(OBJECT_HEADER�����TypeIndex)
				{
					TempObject += 0x18;											//�õ�������
					if (CompareObjectName((PVOID)TempObject, FileName))			//�Ƚ϶����Ƿ�������Ҫ�ҵ�
					{
						if (CurrentProcess == PsGetCurrentProcess())			//�����ǰ�Ľ��̾��ǵ�ǰ�Ľ����ǾͲ���Ҫ�ҿ���ȥ��������Ҫ�ҿ���ȥ
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
	else if (TableCode & 2)													//����һ��������������һ��ָ��һ��4k��ҳ�棬��1024�����飬ÿ������ָ��һ��4k��ҳ�棬ÿ��ҳ����1024�����飬ÿ������ָ��һ��4k��ҳ�棬ÿ��ҳ�汣��512��HandleTableEntry
	{
		TableCode = TableCode & 0xFFFFFFF4;									//��Ȼ������1��������λ�Ϳ����ˣ�����Ϊ��ͳһ�ԣ�������Ȼд���ĩ��λ
		FirstLayer = (ULONG*)TableCode;
		while (*FirstLayer)													//�����ǵ�ǰҳ���ϵ�1024������ÿһ��Ԫ�ض���ֵ������ҵ�һ��Ϊ0�ĵط�Ϊֹ�Ϳ�����
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
					TempObject = TempObject & 0xFFFFFFF8;							//����λ����Ϣλ����������Ϣ�������������Ҫ��յ�
					if (*(UCHAR*)(TempObject + 0xc) == 28)							//���ж��ǲ��ǵ�ǰ��Object�ǲ����ļ� 
					{
						TempObject += 0x18;											//�õ�������
						if (CompareObjectName((PVOID)TempObject, FileName))			//�Ƚ϶����Ƿ�������Ҫ�ҵ�
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
	else																	//����ֻ��һ������ָ��һ��4k��ҳ�棬��512��HandleTableEntry
	{
		TempEntry = (PHANDLE_TABLE_ENTRY)TableCode;
		for (i = 0; i < 512; ++i, ++TempEntry, ++t)
		{
			if (TempEntry->Object == NULL)
				continue;
			TempObject = (ULONG)TempEntry->Object;
			TempObject = TempObject & 0xFFFFFFF8;							//����λ����Ϣλ����������Ϣ�������������Ҫ��յ�
			if (*(UCHAR*)(TempObject + 0xc) == 28)							//���ж��ǲ��ǵ�ǰ��Object�ǲ����ļ� 
			{
				TempObject += 0x18;											//�õ�������
				if (CompareObjectName((PVOID)TempObject, FileName))			//�Ƚ϶����Ƿ�������Ҫ�ҵ�
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
		if (*(ULONG*)((ULONG)TempList + 0x3c) != 0)					//�жϣ�����������ڣ�������������̣�
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