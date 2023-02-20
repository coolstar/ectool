// ectool.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <Windows.h>
#include <stdio.h>

typedef struct _CROSEC_COMMAND {
    UINT32 Version;
    UINT32 Command;
    UINT32 OutSize;
    UINT32 InSize;
    UINT32 Result;
    UINT8 Data[];
} CROSEC_COMMAND, * PCROSEC_COMMAND;

#define FILE_DEVICE_CROS_EMBEDDED_CONTROLLER 0x80EC

#define IOCTL_CROSEC_XCMD \
	CTL_CODE(FILE_DEVICE_CROS_EMBEDDED_CONTROLLER, 0x801, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
#define IOCTL_CROSEC_RDMEM CTL_CODE(FILE_DEVICE_CROS_EMBEDDED_CONTROLLER, 0x802, METHOD_BUFFERED, FILE_READ_DATA)

int ec_command(int cmd, int version, const void* outdata, int outsize, void* indata, int insize) {
    HANDLE device = CreateFileW(L"\\\\.\\GLOBALROOT\\Device\\CrosEC", GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (device == INVALID_HANDLE_VALUE || !device) {
        printf("Failed to open CrosEC driver\n");
        return -1;
    }

    size_t size = sizeof(CROSEC_COMMAND) + max(outsize, insize);
    PCROSEC_COMMAND cmdStruct = (PCROSEC_COMMAND)malloc(size);
    if (!cmdStruct) {
        printf("Failed to allocate cmd struct\n");
        return -1;
    }
    RtlZeroMemory(cmdStruct, size);

    cmdStruct->Version = version;
    cmdStruct->Command = cmd;
    cmdStruct->OutSize = outsize;
    cmdStruct->InSize = insize;
    cmdStruct->Result = 0xff;

    RtlCopyMemory(cmdStruct->Data, outdata, outsize);

    DWORD ret = 0;
    if (!DeviceIoControl(device, IOCTL_CROSEC_XCMD, cmdStruct, (DWORD)size, cmdStruct, (DWORD)size, &ret, NULL)) {
        printf("IOCTL failed\n");
        return -1;
    }

    RtlCopyMemory(indata, cmdStruct->Data, insize);
    return 0;
}

#include <pshpack4.h>

struct ec_response_get_version {
    /* Null-terminated version strings for RO, RW */
    char version_string_ro[32];
    char version_string_rw[32];
    char reserved[32];       /* Was previously RW-B string */
    UINT32 current_image;  /* One of ec_current_image */
};

#include <poppack.h>

/* Get version number */
#define EC_CMD_GET_VERSION 0x02

int main()
{
    struct ec_response_get_version r;
    int rv = ec_command(EC_CMD_GET_VERSION, 0, NULL, 0, &r, sizeof(struct ec_response_get_version));

    if (rv >= 0) {
        /* Ensure versions are null-terminated before we print them */
        r.version_string_ro[sizeof(r.version_string_ro) - 1] = '\0';
        r.version_string_rw[sizeof(r.version_string_rw) - 1] = '\0';

        printf("EC RO Version: %s\n", r.version_string_ro);
        printf("EC RW Version: %s\n", r.version_string_rw);
    }
    else {
        printf("Error: Could not get version\n");
    }
    return 0;
}
