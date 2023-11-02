#include <ntifs.h>
#include "Disk.h"
#include "Nic.h"
#include "Smbios.h"

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT pDrvObj, PUNICODE_STRING pRegistryPath)
{
	UNREFERENCED_PARAMETER(pDrvObj);
	UNREFERENCED_PARAMETER(pRegistryPath);
	Disk::DisableSmart();
	Disk::ChangeDiskSerials();
	Nic::SpoofNIC();
	Smbios::ChangeSmbiosSerials();

	return STATUS_SUCCESS;
}