#include "Smbios.h"

#include "Logger.hpp"
#include "Utils.h"

namespace Smbios
{

	NTSTATUS ChangeSmbiosSerials()
	{
		auto* base = Utils::GetModuleBase("ntoskrnl.exe");
		if (!base)
		{
			err("Failed to find ntoskrnl.sys base!\n");
			return STATUS_UNSUCCESSFUL;
		}
		log("ntoskrnl.exe base:%llp\n", base);


		/*  //������һ����Mac��ַ��Ϊ����
		PVOID ExpBootEnvironmentInformationPtr = Utils::FindPatternImage(base, "\x0F\x10\x05\x00\x00\x00\x00\x0F\x11\x00\x8B", "xxx????xx?x");

		Log::Print("ExpBootEnvironmentInformation ptr: %llp\n", ExpBootEnvironmentInformationPtr);
		if (ExpBootEnvironmentInformationPtr) {
			auto* ExpBootEnvironmentInformation = (*(PLONG)((PBYTE)ExpBootEnvironmentInformationPtr + 3) + 7 + (PBYTE)ExpBootEnvironmentInformationPtr);
			Log::Print("ExpBootEnvironmentInformation: %llp\n", ExpBootEnvironmentInformation);
			ULONG64 time = 0;

			KeQuerySystemTime(&time);
			Utils::SpoofBuffer(time, ExpBootEnvironmentInformation, 16);
		}*/


		/*
		fffff800`1d733111 895c2420        mov     dword ptr [rsp+20h],ebx
		fffff800`1d733115 488b0decdf3f00  mov     rcx,qword ptr [nt!WmipSMBiosTablePhysicalAddress (fffff800`1db31108)]
		fffff800`1d73311c 4885c9          test    rcx,rcx
		fffff800`1d73311f 742c            je      nt!WmipFindSMBiosStructure+0x85 (fffff800`1d73314d)
		fffff800`1d733121 8b151ddf3f00    mov     edx,dword ptr [nt!WmipSMBiosTableLength (fffff800`1db31044)]
		fffff800`1d733127 448d4304        lea     r8d,[rbx+4]
		*/
		auto* WmipSMBiosTablePhysicalAddressCall = static_cast<PPHYSICAL_ADDRESS>(Utils::FindPatternImage(base, "\x48\x8B\x0D\x00\x00\x00\x00\x48\x85\xC9\x74\x00\x8b\x15", "xxx????xxxx?xx")); // WmipFindSMBiosStructure -> WmipSMBiosTablePhysicalAddress
		if (!WmipSMBiosTablePhysicalAddressCall)
		{
			err("Failed to find SMBIOS physical address!\n");
			return STATUS_UNSUCCESSFUL;
		}

		
		auto* WmipSMBiosTablePhysicalAddress = Utils::translateAddress<PPHYSICAL_ADDRESS>(WmipSMBiosTablePhysicalAddressCall, 7);
		if (!WmipSMBiosTablePhysicalAddress)
		{
			err("Physical address is null!\n");
			return STATUS_UNSUCCESSFUL;
		}
		log("WmipSMBiosTablePhysicalAddress:0x%llp\n", WmipSMBiosTablePhysicalAddress);


		/*
		* WmipFindSMBiosStructure + 0x98
		fffff802`0fb3c160 8b15dede3f00    mov     edx,dword ptr [nt!WmipSMBiosTableLength (fffff802`0ff3a044)]
		fffff802`0fb3c166 4803d1          add     rdx,rcx
		fffff802`0fb3c169 c7442420010000c0 mov     dword ptr [rsp+20h],0C0000001h
		fffff802`0fb3c171 483bca          cmp     rcx,rdx
		fffff802`0fb3c174 7339            jae     nt!WmipFindSMBiosStructure+0xe7 (fffff802`0fb3c1af)
		fffff802`0fb3c176 443821          cmp     byte ptr [rcx],r12b
		*/
		auto* WmipSMBiosTableLengthPtr = Utils::FindPatternImage(base, "\x8B\x15\x00\x00\x00\x00\x48\x03\xD1\xC7\x44\x24\x00\x00\x00\x00\x00\x48\x3B\xCA\x73", "xx????xxxxxx?????xxxx");  // WmipFindSMBiosStructure -> WmipSMBiosTableLength
		log("WmipSMBiosTableLength ptr:%llp\n", WmipSMBiosTableLengthPtr);
		if (!WmipSMBiosTableLengthPtr)
		{
			err("Failed to find SMBIOS size!\n");
			return STATUS_UNSUCCESSFUL;
		}

		LONG WmipSMBiosTableLength = *Utils::translateAddress<PLONG>(WmipSMBiosTableLengthPtr, 6);
		//const auto WmipSMBiosTableLength = *(PLONG)(*((PLONG)((PBYTE)WmipSMBiosTableLengthPtr + 2)) + (PBYTE)WmipSMBiosTableLengthPtr + 6);

		if (!WmipSMBiosTableLength)
		{
			err("SMBIOS size is null!\n");
			return STATUS_UNSUCCESSFUL;
		}

		log("WmipSMBiosTableLength:%lx\n", WmipSMBiosTableLength);

		//return 0;

#ifdef __LOOP_TABLE__
		auto* mapped = MmMapIoSpace(*WmipSMBiosTablePhysicalAddress, WmipSMBiosTableLength, MmNonCached);
		if (!mapped)
		{
			Log::Print("Failed to map SMBIOS structures!\n");
			return STATUS_UNSUCCESSFUL;
		}

		LoopTables(mapped, WmipSMBiosTableLength);

		MmUnmapIoSpace(mapped, WmipSMBiosTableLength);

#else // zero   ��ѯsmbios��ʱ��ᷢ���Ҳ���ʵ��

		memset(WmipSMBiosTablePhysicalAddress, 0, sizeof(PPHYSICAL_ADDRESS));
#endif
		log("ChangeSmbiosSerials Status:Success\n");
		return STATUS_SUCCESS;
	}
}

