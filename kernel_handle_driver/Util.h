#pragma once

#include <ntifs.h>
#include <ntddk.h>

extern "C" NTSTATUS IoCreateDriver(IN PUNICODE_STRING DriverName OPTIONAL, IN PDRIVER_INITIALIZE InitializationFunction);

typedef struct _KLDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	PVOID ExceptionTable;
	UINT32 ExceptionTableSize;
	PVOID GpValue;
	struct _NON_PAGED_DEBUG_INFO* NonPagedDebugInfo;
	PVOID ImageBase;
	PVOID EntryPoint;
	UINT32 SizeOfImage;
	UNICODE_STRING FullImageName;
	UNICODE_STRING BaseImageName;
	UINT32 Flags;
	UINT16 LoadCount;

	union
	{
		UINT16 SignatureLevel : 4;
		UINT16 SignatureType : 3;
		UINT16 Unused : 9;
		UINT16 EntireField;
	} u;

	PVOID SectionPointer;
	UINT32 CheckSum;
	UINT32 CoverageSectionSize;
	PVOID CoverageSection;
	PVOID LoadedImports;
	PVOID Spare;
	UINT32 SizeOfImageNotRounded;
	UINT32 TimeDateStamp;
} KLDR_DATA_TABLE_ENTRY, * PKLDR_DATA_TABLE_ENTRY;

typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _DEVICE_MAP* PDEVICE_MAP;

typedef struct _OBJECT_DIRECTORY_ENTRY
{
	_OBJECT_DIRECTORY_ENTRY* ChainLink;
	PVOID Object;
	ULONG HashValue;
} OBJECT_DIRECTORY_ENTRY, * POBJECT_DIRECTORY_ENTRY;

typedef struct _OBJECT_DIRECTORY
{
	POBJECT_DIRECTORY_ENTRY HashBuckets[37];
	EX_PUSH_LOCK Lock;
	PDEVICE_MAP DeviceMap;
	ULONG SessionId;
	PVOID NamespaceEntry;
	ULONG Flags;
} OBJECT_DIRECTORY, * POBJECT_DIRECTORY;

__forceinline wchar_t locase_w(wchar_t c)
{
	if ((c >= 'A') && (c <= 'Z'))
		return c + 0x20;
	else
		return c;
}

int _strcmpi_w(const wchar_t* s1, const wchar_t* s2)
{
	wchar_t c1, c2;

	if (s1 == s2)
		return 0;

	if (s1 == 0)
		return -1;

	if (s2 == 0)
		return 1;

	do {
		c1 = locase_w(*s1);
		c2 = locase_w(*s2);
		s1++;
		s2++;
	} while ((c1 != 0) && (c1 == c2));

	return (int)(c1 - c2);
}

//nice implementation but doenst work with kdmapper
void* GetKernelBaseAddr(IN PDRIVER_OBJECT DriverObject)
{
	PLDR_DATA_TABLE_ENTRY entry = (PLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection;
	PLDR_DATA_TABLE_ENTRY first = entry;
	while ((PLDR_DATA_TABLE_ENTRY)entry->InLoadOrderLinks.Flink != first)
	{
		if (_strcmpi_w(entry->BaseDllName.Buffer, L"ntoskrnl.exe") == 0) return entry->DllBase;
		entry = (PLDR_DATA_TABLE_ENTRY)entry->InLoadOrderLinks.Flink;
	}
	return 0;
}



//KD MAPPER REGION

typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR  FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemBasicInformation,
	SystemProcessorInformation,
	SystemPerformanceInformation,
	SystemTimeOfDayInformation,
	SystemPathInformation,
	SystemProcessInformation,
	SystemCallCountInformation,
	SystemDeviceInformation,
	SystemProcessorPerformanceInformation,
	SystemFlagsInformation,
	SystemCallTimeInformation,
	SystemModuleInformation = 0x0B
} SYSTEM_INFORMATION_CLASS,
* PSYSTEM_INFORMATION_CLASS;


extern "C" NTSTATUS ZwQuerySystemInformation(ULONG InfoClass, PVOID Buffer, ULONG Length, PULONG ReturnLength);


// this implementations works with kdmapped
// based on: https://github.com/NMan1/OverflowRust/blob/master/OverflowDriver/cleaner.h
PVOID get_kernel_base()
{
	NTSTATUS status = STATUS_SUCCESS;
	ULONG bytes = 0;
	PRTL_PROCESS_MODULES pMods = NULL;
	PVOID checkPtr = NULL;
	UNICODE_STRING routineName;
	PVOID ImageBase = NULL;

	RtlInitUnicodeString(&routineName, L"NtOpenFile");

	checkPtr = MmGetSystemRoutineAddress(&routineName);
	if (checkPtr == NULL)
	{
		return NULL;
	}

	status = ZwQuerySystemInformation(SystemModuleInformation, 0, bytes, &bytes);

	if (bytes == 0)
	{
		return NULL;
	}

	pMods = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, bytes, 0x454E4F45); // 'ENON'
	RtlZeroMemory(pMods, bytes);

	status = ZwQuerySystemInformation(SystemModuleInformation, pMods, bytes, &bytes);

	if (NT_SUCCESS(status))
	{
		PRTL_PROCESS_MODULE_INFORMATION pMod = pMods->Modules;

		for (ULONG i = 0; i < pMods->NumberOfModules; i++)
		{
			// System routine is inside module
			if (checkPtr >= pMod[i].ImageBase &&
				checkPtr < (PVOID)((PUCHAR)pMod[i].ImageBase + pMod[i].ImageSize))
			{
				ImageBase = pMod[i].ImageBase;
				break;
			}
		}
	}
	if (pMods)
	{
		ExFreePoolWithTag(pMods, 0x454E4F45); // 'ENON'
	}
	return ImageBase;
}

// based on https://github.com/not-wlan/driver-hijack
extern "C" PDRIVER_OBJECT FindDriver(PUNICODE_STRING targetName)
{
	HANDLE handle{};
	OBJECT_ATTRIBUTES attributes{};
	UNICODE_STRING directory_name{};
	PVOID directory{};

	RtlInitUnicodeString(&directory_name, L"\\Driver");
	InitializeObjectAttributes(&attributes, &directory_name, OBJ_CASE_INSENSITIVE, NULL, NULL);

	// open OBJECT_DIRECTORY for \Driver
	auto status = ZwOpenDirectoryObject(&handle, DIRECTORY_ALL_ACCESS, &attributes);

	if (!NT_SUCCESS(status))
	{
		DbgPrintEx(0, 0, "[Error] - Failed to ZwOpenDirectoryObject %x\n", status);
		return nullptr;
	}

	// Get OBJECT_DIRECTORY pointer from HANDLE
	status = ObReferenceObjectByHandle(handle, DIRECTORY_ALL_ACCESS, nullptr, KernelMode, &directory, nullptr);

	if (!NT_SUCCESS(status))
	{
		DbgPrintEx(0, 0, "[Error] - Failed to ObReferenceObjectByHandle %x\n", status);
		ZwClose(handle);
		return nullptr;
	}

	const auto directory_object = POBJECT_DIRECTORY(directory);
	ExAcquirePushLockExclusiveEx(&directory_object->Lock, 0);

	// traverse hash table with 37 entries
	// when a new object is created, the object manager computes a hash value in the range zero to 36 from the object name and creates an OBJECT_DIRECTORY_ENTRY.    
	// http://www.informit.com/articles/article.aspx?p=22443&seqNum=7
	for (auto entry : directory_object->HashBuckets)
	{
		if (entry == nullptr)
		{
			continue;
		}

		while (entry != nullptr && entry->Object != nullptr)
		{
			// You could add type checking here with ObGetObjectType but if that's wrong we're gonna bsod anyway :P
			auto driver = PDRIVER_OBJECT(entry->Object);

			if (targetName && RtlCompareUnicodeString(&driver->DriverName, targetName, FALSE) == 0)
			{
				ExReleasePushLockExclusiveEx(&directory_object->Lock, 0);

				// Release the acquired resources back to the OS
				ObDereferenceObject(directory);
				ZwClose(handle);

				return driver;
			}
			entry = entry->ChainLink;
		}
	}
	ExReleasePushLockExclusiveEx(&directory_object->Lock, 0);
	ObDereferenceObject(directory);
	ZwClose(handle);
	return nullptr;
}

void GetProcessNameFromId(HANDLE processId, PUNICODE_STRING* name)
{
	PEPROCESS process = NULL;
	PsLookupProcessByProcessId(processId, &process);
	SeLocateProcessImageName(process, name);
}