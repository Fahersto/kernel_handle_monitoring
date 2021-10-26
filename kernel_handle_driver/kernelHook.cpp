/**
* Registers an ObRegisterCallack from an unsigned (kdmapped) driver by abusing a "JMP RCX" instruction in a legit driver (original idea: https://www.unknowncheats.me/forum/2350590-post9.html) 
*
*/

#include <ntifs.h>
#include <ntddk.h>
#include "Util.h"

#define IOCTL_MONITOR_HANDLES_OF_PROCESS  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x4711, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define PROCESS_VM_OPERATION               (0x0008)  
#define PROCESS_VM_WRITE                   (0x0020)  

// Kernel-Mode Process and Thread Manager callbacks
BOOLEAN monitorThreadCreation = 0;
BOOLEAN monitorProcessCreation = 0;
BOOLEAN monitorImageLoading = 0;

// ObRegisterCallback
BOOLEAN monitorHandleOperationPreCallback = 1;
BOOLEAN monitorHandleOperationPostCallback = 0;
BOOLEAN ignoreHandlesToOwnProcess = 1;

PVOID obCallbackRegistrationHandle = NULL;

HANDLE currentlyMonitoredProcess = NULL;

NTSTATUS IOCTL_DispatchRoutine(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	PIO_STACK_LOCATION stackLocation = NULL;
	CHAR* successMessage = "[Info] - Driver is monitoring process";
	CHAR* errorMessage = "[Error] - Driver could not find processId";
	CHAR* message = "";

	DbgPrintEx(0, 0, "[Info] - Received IOCTL request\n");

	stackLocation = IoGetCurrentIrpStackLocation(Irp);
	if (stackLocation->Parameters.DeviceIoControl.IoControlCode == IOCTL_MONITOR_HANDLES_OF_PROCESS)
	{
		PHANDLE handle = (PHANDLE)Irp->AssociatedIrp.SystemBuffer;

		DbgPrintEx(0, 0, "[Info] - Received request to monitor process %p\n", *handle);

		PEPROCESS process = NULL;
		PUNICODE_STRING processName = NULL;
		NTSTATUS status = 0;
		status = PsLookupProcessByProcessId(*handle, &process);
		if (!NT_SUCCESS(status))
		{
			DbgPrintEx(0, 0, "[Error] - Failed to lookup process id %p\n", *handle);
			message = errorMessage;
		}
		else
		{
			currentlyMonitoredProcess = *handle;
			message = successMessage;
			SeLocateProcessImageName(process, &processName);
			DbgPrintEx(0, 0, "[Info] - Monitoring process %wZ\n", processName);
		}
	}

	Irp->IoStatus.Information = strlen(message);
	Irp->IoStatus.Status = STATUS_SUCCESS;

	RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, message, strlen(message));
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS MajorFunctions(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	PIO_STACK_LOCATION stackLocation = NULL;
	stackLocation = IoGetCurrentIrpStackLocation(Irp);
	switch (stackLocation->MajorFunction)
	{
	case IRP_MJ_CREATE:
		DbgPrintEx(0, 0, "[Info] - Handle to symbolink link opened\n");
		break;
	case IRP_MJ_CLOSE:
		DbgPrintEx(0, 0, "[Info] - Handle to symbolink link closed\n");
		break;
	default:
		break;
	}
	Irp->IoStatus.Information = 0;
	Irp->IoStatus.Status = STATUS_SUCCESS;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
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

// called before a handle operation occures
// https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nc-wdm-pob_pre_operation_callback
OB_PREOP_CALLBACK_STATUS PreHandleOperationCallback(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION pOperationInformation)
{
	UNREFERENCED_PARAMETER(RegistrationContext);

	if (!monitorHandleOperationPreCallback || !currentlyMonitoredProcess || PsGetProcessId(PsGetCurrentProcess()) != currentlyMonitoredProcess)
	{
		return OB_PREOP_SUCCESS;
	}

	// get the name of the calling process
	// this can be done because this callback runs in the context of the calling process
	PUNICODE_STRING currentProcessName = NULL;
	HANDLE currentProcessId = PsGetProcessId(PsGetCurrentProcess());
	GetProcessNameFromId(currentProcessId, &currentProcessName);

	DbgPrintEx(0, 0, "[Info] - Handle operation PreCallback - %wZ\n", currentProcessName);

	if (pOperationInformation->Operation == OB_OPERATION_HANDLE_CREATE)
	{
		ULONG desiredAccess = pOperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess;
		PVOID targetObject = pOperationInformation->Object;
		POBJECT_TYPE targetObjectType = pOperationInformation->ObjectType;

		if (targetObjectType == *PsProcessType)
		{
			PUNICODE_STRING processName = NULL;
			HANDLE targetProcessId = PsGetProcessId((PEPROCESS)targetObject);
			GetProcessNameFromId(targetProcessId, &processName);

			if (ignoreHandlesToOwnProcess && currentProcessId == targetProcessId)
			{
				return OB_PREOP_SUCCESS;
			}
			DbgPrintEx(0, 0, "\tCreating handle to process %wZ(%p) with access %lx\n", processName, targetObject, desiredAccess);
			if ((desiredAccess & PROCESS_VM_WRITE) && (desiredAccess & PROCESS_VM_OPERATION))
			{
				DbgPrintEx(0, 0, "\t--> This handle can be used to WPM\n");
			}
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

		PUNICODE_STRING processName = NULL;
		GetProcessNameFromId(PsGetProcessId((PEPROCESS)targetObject), &processName);

		PUNICODE_STRING sourceProcessName = NULL;
		GetProcessNameFromId(PsGetProcessId((PEPROCESS)sourceProcess), &sourceProcessName);

		PUNICODE_STRING targetProcessName = NULL;
		GetProcessNameFromId(PsGetProcessId((PEPROCESS)targetProcess), &targetProcessName);

		if (targetObjectType == *PsProcessType)
		{
			DbgPrintEx(0, 0, "\tDuplicating handle to process %wZ(%p) with access %lx (source: %wZ, target: %wZ)\n", processName, targetObject, desiredAccess, sourceProcessName, targetProcessName);
			if ((desiredAccess & PROCESS_VM_WRITE) && (desiredAccess & PROCESS_VM_OPERATION))
			{
				DbgPrintEx(0, 0, "\t--> This handle can be used to WPM\n");
			}
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

// will not be called since there is no easy way of unloading when kdmapping the driver
void DriverUnload(PDRIVER_OBJECT dob)
{
	UNREFERENCED_PARAMETER(dob);
	DbgPrintEx(0, 0, "[Info] - Unloading cikh driver\n");

	PsSetCreateProcessNotifyRoutineEx(CreateProcessNotification_Callback, TRUE);
	PsRemoveCreateThreadNotifyRoutine(CreateThreadNotification_Callback);
	PsRemoveLoadImageNotifyRoutine(LoadImageNotification_Callback);
	ObUnRegisterCallbacks(obCallbackRegistrationHandle);

	//IoDeleteDevice(dob->DeviceObject);
	//IoDeleteSymbolicLink(&DEVICE_SYMBOLIC_NAME);
}

NTSTATUS RegisterObRegisterCallback(POB_PRE_OPERATION_CALLBACK preOperationCallback)
{
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
	obOperationRegistration.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;

	// the pre operation is called before the operation occures
	obOperationRegistration.PreOperation = preOperationCallback;

	// the post operaton is called after the operation occured
	//obOperationRegistration.PostOperation = (POB_POST_OPERATION_CALLBACK)jmpRcx;

	obCallbackRegistration.OperationRegistration = &obOperationRegistration;

	// register the callback
	return ObRegisterCallbacks(&obCallbackRegistration, &obCallbackRegistrationHandle);
}


PVOID FindJmpRcxInstruction(unsigned char* startAddress, int searchLength)
{
	for (int i = 0; i < searchLength; i++)
	{
		// FF E1  jmp rcx
		if (startAddress[i] == 0xff && startAddress[i + 1] == 0xe1)
		{
			return startAddress + i;
		}
	}
	return nullptr;
}

NTSTATUS RealEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	//UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);

	NTSTATUS status = 0;

	DbgPrintEx(0, 0, "[Info] - RealEntry called\n");
	DbgPrintEx(0, 0, "\tDriverObject %p\n", DriverObject);

	// when mapped with kdmapper it is expected that DriverSection is NULL
	// this serves as a reminder, that we don't have a valid driver when mapping it
	DbgPrintEx(0, 0, "\tDriverSection %p\n", DriverObject->DriverSection);

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

	PVOID jmpRcx = FindJmpRcxInstruction((unsigned char*)targetDriver->DriverStart, 0x100000);
	if (!jmpRcx)
	{
		DbgPrintEx(0, 0, "[Error] - Failed to find \"JMP RCX\" in %wZ\n", targetDriver->DriverName);
		return STATUS_UNSUCCESSFUL;
	}

	DbgPrintEx(0, 0, "[Info] - Found \"JMP RCX\" in %wZ at address %p\n", targetDriver->DriverName, jmpRcx);

	status = RegisterObRegisterCallback((POB_PRE_OPERATION_CALLBACK)jmpRcx);
	if (!NT_SUCCESS(status))
	{
		DbgPrintEx(0, 0, "[Error] - Failed ObRegisterCallbacks: %x\n", status);
		return status;
	}

	DbgPrintEx(0, 0, "[Info] - ObRegisterCallbacks registered successfully\n");

	UNICODE_STRING deviceName;
	RtlInitUnicodeString(&deviceName, L"\\Device\\cikhdevice");
	
	status = IoCreateDevice(DriverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &DriverObject->DeviceObject);
	if (!NT_SUCCESS(status))
	{
		DbgPrintEx(0, 0, "[Error] - Failed to IoCreateDevice %wZ\n", deviceName);
		return status;
	}

	DbgPrintEx(0, 0, "[Info] - IoDevice created successfully\n");

	UNICODE_STRING symbolicLinkName;
	RtlInitUnicodeString(&symbolicLinkName, L"\\DosDevices\\cikhlink");
	status = IoCreateSymbolicLink(&symbolicLinkName, &deviceName);
	if (!NT_SUCCESS(status))
	{
		DbgPrintEx(0, 0, "[Error] - Failed to IoCreateSymbolicLink %wZ\n", symbolicLinkName);
		return status;
	}

	DbgPrintEx(0, 0, "[Info] - IoSymbolicLink created successfully\n");

	DriverObject->DriverUnload = DriverUnload;

	// routine for handling IO requests from userland
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IOCTL_DispatchRoutine;

	// routines that will execute once a handle to our device's symbolik link is opened/closed
	DriverObject->MajorFunction[IRP_MJ_CREATE] = MajorFunctions;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = MajorFunctions;

	// https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/clearing-the-do-device-initializing-flag
	// this flag should be cleared after attaching the device object
	// not doing so may break IOCTL communication
	ClearFlag(DriverObject->DeviceObject->Flags, DO_DEVICE_INITIALIZING);

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