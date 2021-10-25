#include <iostream>
#include <Windows.h>

#define IOCTL_MONITOR_HANDLES_OF_PROCESS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x4711, METHOD_BUFFERED, FILE_ANY_ACCESS)

/**
*  User mode application to controll the code_injection_kernel_hooking driver
*
*/
int main(char argc, char** argv)
{
    if (argc != 2)
    {
        printf("Usage: *.exe targetProcessId\n");
        return 1;
    }

    int64_t targetProcessId = atoi(argv[1]);
    PHANDLE pTargetProcessId = (PHANDLE)&targetProcessId;

    // open I/O device created by the driver
    HANDLE ioDevice = CreateFileA("\\\\.\\cikhlink", GENERIC_READ, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (ioDevice == INVALID_HANDLE_VALUE)
    {
        printf("Error %d - Failed to open driver device", GetLastError());
        return 1;
    }

    printf("[Info] - Sending IOCTL control code %x to driver\n", IOCTL_MONITOR_HANDLES_OF_PROCESS);

    char driverResponseBuffer[128] = {0};
    DWORD bytesReturned = 0;

    // send control code to specified device driver
    if (!DeviceIoControl(ioDevice, IOCTL_MONITOR_HANDLES_OF_PROCESS, pTargetProcessId, sizeof(pTargetProcessId), driverResponseBuffer, sizeof(driverResponseBuffer), &bytesReturned, NULL))
    {
        printf("Error %d - Failed to communicate with driver\n", GetLastError());
    }
    printf("Driver responded with %d bytes: %s\n", bytesReturned, driverResponseBuffer);

    CloseHandle(ioDevice);
}