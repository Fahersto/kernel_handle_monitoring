#include <ntifs.h>
#include <ntddk.h>

#include "Util.h"


extern "C" NTSTATUS IoCreateDriver(IN PUNICODE_STRING DriverName OPTIONAL, IN PDRIVER_INITIALIZE InitializationFunction);

/**/
DRIVER_DISPATCH IOCTL_DispatchRoutine;

#define IOCTL_MONITOR_HANDLES_OF_PROCESS  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x4711, METHOD_BUFFERED, FILE_ANY_ACCESS)

//UNICODE_STRING DEVICE_NAME = RTL_CONSTANT_STRING(L"\\Device\\cikhdriver");
//UNICODE_STRING DEVICE_SYMBOLIC_NAME = RTL_CONSTANT_STRING(L"\\DosDevices\\cikhdriver");

// Kernel-Mode Process and Thread Manager callbacks
BOOLEAN monitorThreadCreation = 0;
BOOLEAN monitorProcessCreation = 0;
BOOLEAN monitorImageLoading = 0;

// ObRegisterCallback
BOOLEAN monitorHandleOperationPreCallback = 1;
BOOLEAN monitorHandleOperationPostCallback = 0;

PVOID obCallbackRegistrationHandle = NULL;

HANDLE currentlyMonitoredProcess = NULL;
extern POBJECT_TYPE* IoDriverObjectType;

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


NTSTATUS IOCTL_DispatchRoutine(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	PIO_STACK_LOCATION stackLocation = NULL;
	CHAR* successMessage = "[Info] - Driver is monitoring process";
	CHAR* errorMessage = "[Error] - Driver could not find processId";
	CHAR* message = "hi";

	DbgPrintEx(0, 0, "[Info] - IOCTL_DispatchRoutine\n");

	stackLocation = IoGetCurrentIrpStackLocation(Irp);
	if (stackLocation->Parameters.DeviceIoControl.IoControlCode == IOCTL_MONITOR_HANDLES_OF_PROCESS)
	{
		DbgPrintEx(0, 0, "[Info] - Received IOCTL_MONITOR_HANDLES_OF_PROCESS %lx\n", stackLocation->Parameters.DeviceIoControl.IoControlCode);

		PHANDLE handle = (PHANDLE)Irp->AssociatedIrp.SystemBuffer;
		DbgPrintEx(0, 0, "\tMonitor process %p\n", *handle);

		PEPROCESS process = NULL;
		PUNICODE_STRING processName = NULL;
		NTSTATUS status = 0;
		status = PsLookupProcessByProcessId(*handle, &process);
		if (!NT_SUCCESS(status))
		{
			message = errorMessage;
		}
		else
		{
			currentlyMonitoredProcess = *handle;
			message = successMessage;
			SeLocateProcessImageName(process, &processName);
		}
	}

	Irp->IoStatus.Information = strlen(message);
	Irp->IoStatus.Status = STATUS_SUCCESS;

	RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, message, strlen(message));

	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}
/*
NTSTATUS MajorFunctions(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	PIO_STACK_LOCATION stackLocation = NULL;
	stackLocation = IoGetCurrentIrpStackLocation(Irp);
	switch (stackLocation->MajorFunction)
	{
	case IRP_MJ_CREATE:
		DbgPrintEx(0, 0, "Handle to symbolink link opened\n");
		break;
	case IRP_MJ_CLOSE:
		DbgPrintEx(0, 0, "Handle to symbolink link closed\n");
		break;
	default:
		break;
	}		Irp->IoStatus.Information = 0;
	Irp->IoStatus.Status = STATUS_SUCCESS;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}
*/

NTSTATUS create_io(PDEVICE_OBJECT device_obj, PIRP irp) {
	UNREFERENCED_PARAMETER(device_obj);

	DbgPrintEx(0, 0, "[Info] - IOCTL create\n");

	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return irp->IoStatus.Status;
}

NTSTATUS close_io(PDEVICE_OBJECT device_obj, PIRP irp) {
	UNREFERENCED_PARAMETER(device_obj);

	DbgPrintEx(0, 0, "[Info] - IOCTL close\n");

	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return irp->IoStatus.Status;
}

// called when a thread is created or deleted
// https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nc-ntddk-pcreate_thread_notify_routine
void CreateThreadNotification_Callback(HANDLE ProcessId, HANDLE ThreadId, BOOLEAN Create)
{
	UNREFERENCED_PARAMETER(ThreadId);

	if (!monitorThreadCreation)
	{
		return;
	}

	if (Create)
	{
		PEPROCESS process = NULL;
		PUNICODE_STRING processName = NULL;
		PsLookupProcessByProcessId(ProcessId, &process);
		SeLocateProcessImageName(process, &processName);
		//DbgPrintEx(0, 0, "[Info] - Process %wZ(%p) created thread %p\n", processName, ProcessId, ThreadId);
	}
	else
	{
		//DbgPrintEx(0, 0, "[Info] - Process %p deleted thread %p\n", ProcessId, ThreadId);
	}
}

// called when a process is created or exits
// https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nc-ntddk-pcreate_process_notify_routine_ex
void CreateProcessNotification_Callback(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo)
{
	UNREFERENCED_PARAMETER(Process);
	UNREFERENCED_PARAMETER(ProcessId);

	if (!monitorProcessCreation)
	{
		return;
	}

	DbgPrintEx(0, 0, "[Info] - CreateProcessNotificationRoutine called\n");

	if (CreateInfo != NULL)
	{
		DbgPrintEx(0, 0, "\tCreating process for image %wZ\n", CreateInfo->ImageFileName);
	}
}

// called when an image is mapped into memory (loaded)
// https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nc-ntddk-pload_image_notify_routine
void LoadImageNotification_Callback(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo)
{
	if (!monitorImageLoading)
	{
		return;
	}

	DbgPrintEx(0, 0, "[Info] - LoadImageNotification_Callback\n");
	if (FullImageName && ProcessId && ImageInfo)
	{
		PEPROCESS process = NULL;
		PUNICODE_STRING processName = NULL;

		PsLookupProcessByProcessId(ProcessId, &process);
		SeLocateProcessImageName(process, &processName);
		DbgPrintEx(0, 0, "\tProcess %wZ(%p) loaded image %wZ at %p\n", processName, ProcessId, FullImageName, ImageInfo->ImageBase);
	}
}

void GetProcessNameFromId(HANDLE processId, PUNICODE_STRING* name)
{
	PEPROCESS process = NULL;
	PsLookupProcessByProcessId(processId, &process);
	SeLocateProcessImageName(process, name);
}

// called before a handle operation occures
// https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nc-wdm-pob_pre_operation_callback
OB_PREOP_CALLBACK_STATUS PreHandleOperationCallback(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION pOperationInformation)
{
	UNREFERENCED_PARAMETER(RegistrationContext);

	//DbgPrintEx(0, 0, "~~~ PreHandleOperationCallback ~~~\n");

	if (!monitorHandleOperationPreCallback)
	{
		return OB_PREOP_SUCCESS;
	}

	if (!currentlyMonitoredProcess || PsGetProcessId(PsGetCurrentProcess()) != currentlyMonitoredProcess)
	{
		return OB_PREOP_SUCCESS;
	}

	PUNICODE_STRING currentProcessName = NULL;
	GetProcessNameFromId(PsGetProcessId(PsGetCurrentProcess()), &currentProcessName);

	if (pOperationInformation->Operation == OB_OPERATION_HANDLE_CREATE)
	{
		ULONG desiredAccess = pOperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess;
		PVOID targetObject = pOperationInformation->Object;
		POBJECT_TYPE targetObjectType = pOperationInformation->ObjectType;

		// only print all acess for the time being
		// TODO disable when doing live tests
		//if (desiredAccess != PROCESS_ALL_ACCESS)
		//{
		//	return OB_PREOP_SUCCESS;
		//}

		DbgPrintEx(0, 0, "[Info] - Handle operation PreCallback - %wZ\n", currentProcessName);

		if (targetObjectType == *PsProcessType)
		{
			PUNICODE_STRING processName = NULL;
			GetProcessNameFromId(PsGetProcessId((PEPROCESS)targetObject), &processName);

			DbgPrintEx(0, 0, "\tCreating handle to process %wZ(%p) with access %lx\n", processName, targetObject, desiredAccess);
		}
		else // PsThreadType
		{
			DbgPrintEx(0, 0, "\tCreating handle to thread %p with access %lx\n", targetObject, desiredAccess);
		}

	}
	else // OB_OPERATION_HANDLE_DUPLICATE
	{
		ULONG desiredAccess = pOperationInformation->Parameters->DuplicateHandleInformation.OriginalDesiredAccess;
		PVOID targetObject = pOperationInformation->Object;
		POBJECT_TYPE targetObjectType = pOperationInformation->ObjectType;
		PVOID sourceProcess = pOperationInformation->Parameters->DuplicateHandleInformation.SourceProcess;
		PVOID targetProcess = pOperationInformation->Parameters->DuplicateHandleInformation.TargetProcess;

		// only print all acess for the time being
		// TODO disable when doing live tests
		//if (desiredAccess != PROCESS_ALL_ACCESS)
		//{
		//	return OB_PREOP_SUCCESS;
		//}

		DbgPrintEx(0, 0, "[Info] - Handle operation PreCallback - %wZ\n", currentProcessName);

		PUNICODE_STRING processName = NULL;
		GetProcessNameFromId(PsGetProcessId((PEPROCESS)targetObject), &processName);

		PUNICODE_STRING sourceProcessName = NULL;
		GetProcessNameFromId(PsGetProcessId((PEPROCESS)sourceProcess), &sourceProcessName);

		PUNICODE_STRING targetProcessName = NULL;
		GetProcessNameFromId(PsGetProcessId((PEPROCESS)targetProcess), &targetProcessName);

		if (targetObjectType == *PsProcessType)
		{
			DbgPrintEx(0, 0, "\tDuplicating handle to process %wZ(%p) with access %lx (source: %wZ, target: %wZ)\n", processName, targetObject, desiredAccess, sourceProcessName, targetProcessName);
		}
		else // PsThreadType
		{
			DbgPrintEx(0, 0, "\tDuplicating handle to thread %p with access %lx\n (source: %wZ, target:%wZ)\n", targetObject, desiredAccess, sourceProcessName, targetProcessName);
		}
	}
	return OB_PREOP_SUCCESS;
}

// called after a handle operation occures
// https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nc-wdm-pob_post_operation_callback
void PostHandleOperationCallback(PVOID RegistrationContext, POB_POST_OPERATION_INFORMATION pOperationInformation)
{
	if (!monitorHandleOperationPostCallback)
	{
		return;
	}

	UNREFERENCED_PARAMETER(RegistrationContext);
	UNREFERENCED_PARAMETER(pOperationInformation);

	DbgPrintEx(0, 0, "[Info] - ObRegisterCallback - Post Callback\n");
}

void DriverUnload(PDRIVER_OBJECT dob)
{
	UNREFERENCED_PARAMETER(dob);
	DbgPrintEx(0, 0, "[Info] - Unloading KernelHook driver\n");

	PsSetCreateProcessNotifyRoutineEx(CreateProcessNotification_Callback, TRUE);
	PsRemoveCreateThreadNotifyRoutine(CreateThreadNotification_Callback);
	PsRemoveLoadImageNotifyRoutine(LoadImageNotification_Callback);
	ObUnRegisterCallbacks(obCallbackRegistrationHandle);

	//IoDeleteDevice(dob->DeviceObject);
	//IoDeleteSymbolicLink(&DEVICE_SYMBOLIC_NAME);
}

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


// based on https://github.com/not-wlan/driver-hijack
extern "C" PDRIVER_OBJECT FindDriver(PUNICODE_STRING targetName)
{
	HANDLE handle{};
	OBJECT_ATTRIBUTES attributes{};
	UNICODE_STRING directory_name{};
	PVOID directory{};
	BOOLEAN success = FALSE;

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
			continue;

		if (success == TRUE)
			break;

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

			/*
			DbgPrintEx(0, 0, "\tDriver %wZ at %p\n", driver->DriverName, driver);
			if (driver && driver->DeviceObject)
			{
				DbgPrintEx(0, 0, "\tDeviceObject at %p\n", driver->DeviceObject);
				if (driver && driver->DeviceObject)
				{
					DbgPrintEx(0, 0, "\t\tflags at %lx\n", driver->DeviceObject->Flags);
					if (driver->DeviceObject->Flags & 0x20)
					{
						DbgPrintEx(0, 0, "~~~ MAAAAAAAAAAAAATCH ~~~~~~\n");
					}
				}
			}*/
			entry = entry->ChainLink;
		}

	}

	ExReleasePushLockExclusiveEx(&directory_object->Lock, 0);

	// Release the acquired resources back to the OS
	ObDereferenceObject(directory);
	ZwClose(handle);

	return nullptr;
}

NTSTATUS unsupported_io(PDEVICE_OBJECT device_obj, PIRP irp) {
	UNREFERENCED_PARAMETER(device_obj);

	irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return irp->IoStatus.Status;
}

NTSTATUS RealEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	//UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);

	NTSTATUS status = 0;

	DbgPrintEx(0, 0, "[Info] - RealEntry called\n");
	DbgPrintEx(0, 0, "\tDriver object %p\n", DriverObject);

	// when mapped with kdmapper it is expected that DriverSection is NULL
	// this serves as a reminder, that we don't have a valid driver when mapping it
	DbgPrintEx(0, 0, "\tDriver section %p\n", DriverObject->DriverSection);

	UNICODE_STRING  drvName;
	RtlInitUnicodeString(&drvName, L"\\Driver\\DXGKrnl");
	auto targetDriver = FindDriver(&drvName);

	if (!targetDriver)
	{
		DbgPrintEx(0, 0, "[Error] - Failed to find driver %wZ\n", drvName);
		return STATUS_UNSUCCESSFUL;
	}

	DbgPrintEx(0, 0, "[Info] - Found driver %wZ at %p\n", targetDriver->DriverName, targetDriver);

	PKLDR_DATA_TABLE_ENTRY targetDriverSection = (PKLDR_DATA_TABLE_ENTRY)targetDriver->DriverSection;

	// we need the 0x20 flag to be set to be able to register ObRegisterCallbacks
	// ObRegisterCallbacks calls MmVerifyCallbackFunctionCheckFlags which checks for the 0x20 flag
	// MmVerifyCallbackFunctionCheckFlags will look up in which PDRIVER_OBJECT the supplied callbacks (pre and post callbacks) are located
	//	and check the flags of that PDRIVER_OBJECT->DriverSection for 0x20 
	DbgPrintEx(0, 0, "[Info] - PKLDR_DATA_TABLE_ENTRY flags %x\n", targetDriverSection->Flags);

	PVOID jmpRcx = nullptr;
	unsigned char* currentAddress = (unsigned char*)targetDriver->DriverStart;
	for (int i = 0; i < 0x100000; i++)
	{
		// FF E1  jmp rcx
		if (currentAddress[i] == 0xff && currentAddress[i+1] == 0xe1)
		{
			jmpRcx = currentAddress + i;
			DbgPrintEx(0, 0, "[Info] - Found \"jmp rcx\" at %p\n", currentAddress);
			break;
		}
	}

	if (!jmpRcx)
	{
		DbgPrintEx(0, 0, "[Error] - Failed to find \"jmp rcx\" in %wZ\n", targetDriver->DriverName);
		return STATUS_UNSUCCESSFUL;
	}

	// ObRegisterCallback
	OB_CALLBACK_REGISTRATION obCallbackRegistration = { 0, };
	OB_OPERATION_REGISTRATION obOperationRegistration = { 0, };

	// "Drivers should specify OB_FLT_REGISTRATION_VERSION": https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_ob_callback_registration
	obCallbackRegistration.Version = OB_FLT_REGISTRATION_VERSION;

	// OB_OPERATION_REGISTRATION count
	obCallbackRegistration.OperationRegistrationCount = 1;

	// specifies when to load the driver
	// the current value is in the load order group: "Activity Monitor" (360000-389999)
	RtlInitUnicodeString(&obCallbackRegistration.Altitude, L"379482");
	obCallbackRegistration.RegistrationContext = (PVOID)PreHandleOperationCallback;

	obOperationRegistration.ObjectType = PsProcessType; // todo there is also PsThreadType and on windows10 there is ExDesktopObjectType

	// operations the pre- and postcallbacks will be called for
	// it seems there are only OB_OPERATION_HANDLE_CREATE and OB_OPERATION_HANDLE_DUPLICATE
	// https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_ob_operation_registration
	obOperationRegistration.Operations = OB_OPERATION_HANDLE_CREATE;

	// the pre operation is called before the operation occures
	obOperationRegistration.PreOperation = (POB_PRE_OPERATION_CALLBACK)jmpRcx;

	// the post operaton is called after the operation occured
	//obOperationRegistration.PostOperation = (POB_POST_OPERATION_CALLBACK)jmpRcx;

	obCallbackRegistration.OperationRegistration = &obOperationRegistration;

	// register the callback
	status = ObRegisterCallbacks(&obCallbackRegistration, &obCallbackRegistrationHandle);
	if (!NT_SUCCESS(status))
	{
		DbgPrintEx(0, 0, "[Error] - Failed ObRegisterCallbacks: %x\n", status);
		return status;
	}

	DbgPrintEx(0, 0, "[Info] - ObRegisterCallbacks success\n");

	PDEVICE_OBJECT dev_obj;
	UNICODE_STRING dev_name, sym_link;
	RtlInitUnicodeString(&dev_name, L"\\Device\\cikhdevice");

	status = IoCreateDevice(DriverObject, 0, &dev_name, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &dev_obj);
	if (!NT_SUCCESS(status))
	{
		DbgPrintEx(0, 0, "[Error] - Failed to IoCreateDevice %wZ\n", dev_name);
		return status;
	}

	DbgPrintEx(0, 0, "[Info] - IoCreateDevice success\n");

	RtlInitUnicodeString(&sym_link, L"\\DosDevices\\cikhlink");
	status = IoCreateSymbolicLink(&sym_link, &dev_name);
	if (!NT_SUCCESS(status))
	{
		DbgPrintEx(0, 0, "[Error] - Failed to IoCreateSymbolicLink %wZ\n", sym_link);
		return status;
	}

	SetFlag(dev_obj->Flags, DO_BUFFERED_IO); //set DO_BUFFERED_IO bit to 1

	DbgPrintEx(0, 0, "[Info] - IoCreateSymbolicLink success\n");


	for (int t = 0; t <= IRP_MJ_MAXIMUM_FUNCTION; t++) //set all MajorFunction's to unsupported
		DriverObject->MajorFunction[t] = unsupported_io;

	DriverObject->DriverUnload = DriverUnload;

	// routine for handling IO requests from userland
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IOCTL_DispatchRoutine;
	// routines that will execute once a handle to our device's symbolik link is opened/closed
	DriverObject->MajorFunction[IRP_MJ_CREATE] = create_io;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = close_io;

	ClearFlag(dev_obj->Flags, DO_DEVICE_INITIALIZING);
	return STATUS_SUCCESS;
}

// called after the driver is loaded.
// we define DriverEntry as custom entry point and then call our real entry function so we can use kdmapper to load it
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	// invalid for drivers mapped with kdmapper
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);

	NTSTATUS status;
	UNICODE_STRING  drv_name;
	RtlInitUnicodeString(&drv_name, L"\\Driver\\cikhdriver");
	status = IoCreateDriver(&drv_name, &RealEntry);
	if (!NT_SUCCESS(status))
	{
		DbgPrintEx(0, 0, "[Error] - IoCreateDriver failed with status %x\n", status);
		return status;
	}
	return STATUS_SUCCESS;
}