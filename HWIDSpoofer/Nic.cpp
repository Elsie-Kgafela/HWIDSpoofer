#include "Nic.h"

#include "Utils.h"
#include "Logger.hpp"
#include "Shared.h"

namespace Nic
{
	static DWORD SEED = 0;

	PDRIVER_DISPATCH NsiControlOriginal = 0;

	struct {
		DWORD Length;
		NIC_DRIVER Drivers[0xFF];
	} NICs = { 0 };



	

	
	


	NTSTATUS NsiControl(PDEVICE_OBJECT device, PIRP irp) {
		PIO_STACK_LOCATION ioc = IoGetCurrentIrpStackLocation(irp);
		switch (ioc->Parameters.DeviceIoControl.IoControlCode) {
		case IOCTL_NSI_PROXY_ARP: {
			DWORD length = ioc->Parameters.DeviceIoControl.OutputBufferLength;
			NTSTATUS ret = NsiControlOriginal(device, irp);

			PNSI_PARAMS params = (PNSI_PARAMS)irp->UserBuffer;
			if (params && NSI_PARAMS_ARP == params->Type) {
				memset(irp->UserBuffer, 0, length);

				log("handled ARP table\n");
			}

			return ret;
		}
		}

		return NsiControlOriginal(device, irp);
	}







	/**** NIC ****/

	NTSTATUS NICIoc(PDEVICE_OBJECT device, PIRP irp, PVOID context) {
		if (context) {
			IOC_REQUEST request = *(PIOC_REQUEST)context;
			ExFreePool(context);

			if (irp->MdlAddress) {
				Utils::SpoofBuffer(SEED, (PBYTE)MmGetSystemAddressForMdl(irp->MdlAddress), 6);

				log("handled NICIoc\n");
			}

			if (request.OldRoutine && irp->StackCount > 1) {
				return request.OldRoutine(device, irp, request.OldContext);
			}
		}

		return STATUS_SUCCESS;
	}
	PVOID SafeCopy(PVOID src, DWORD size) {
		PCHAR buffer = (PCHAR)ExAllocatePool(NonPagedPool, size);
		if (buffer) {
			MM_COPY_ADDRESS addr = { 0 };
			addr.VirtualAddress = src;

			SIZE_T read = 0;
			if (NT_SUCCESS(MmCopyMemory(buffer, addr, size, MM_COPY_MEMORY_VIRTUAL, &read)) && read == size) {
				return buffer;
			}

			ExFreePool(buffer);
		}
		else {
			err("! failed to allocate pool of size %d !\n", size);
		}

		return 0;
	}
	PWCHAR TrimGUID(PWCHAR guid, DWORD max) {
		DWORD i = 0;
		PWCHAR start = guid;

		--max;
		for (; i < max && *start != L'{'; ++i, ++start);
		for (; i < max && guid[i++] != L'}';);

		guid[i] = 0;
		return start;
	}




	VOID ChangeIoc(PIO_STACK_LOCATION ioc, PIRP irp, PIO_COMPLETION_ROUTINE routine) {
		PIOC_REQUEST request = (PIOC_REQUEST)ExAllocatePool(NonPagedPool, sizeof(IOC_REQUEST));
		if (!request) {
			err("! failed to allocate IOC_REQUEST !\n");
			return;
		}

		request->Buffer = irp->AssociatedIrp.SystemBuffer;
		request->BufferLength = ioc->Parameters.DeviceIoControl.OutputBufferLength;
		request->OldContext = ioc->Context;
		request->OldRoutine = ioc->CompletionRoutine;

		ioc->Control = SL_INVOKE_ON_SUCCESS;
		ioc->Context = request;
		ioc->CompletionRoutine = routine;
	}

	NTSTATUS NICControl(PDEVICE_OBJECT device, PIRP irp) {
		for (DWORD i = 0; i < NICs.Length; ++i) {
			PNIC_DRIVER driver = &NICs.Drivers[i];

			if (driver->Original && driver->DriverObject == device->DriverObject) {
				PIO_STACK_LOCATION ioc = IoGetCurrentIrpStackLocation(irp);
				switch (ioc->Parameters.DeviceIoControl.IoControlCode) {
				case IOCTL_NDIS_QUERY_GLOBAL_STATS: {
					switch (*(PDWORD)irp->AssociatedIrp.SystemBuffer) {
					case OID_802_3_PERMANENT_ADDRESS:
					case OID_802_3_CURRENT_ADDRESS:
					case OID_802_5_PERMANENT_ADDRESS:
					case OID_802_5_CURRENT_ADDRESS:
						ChangeIoc(ioc, irp, NICIoc);
						break;
					}

					break;
				}
				}

				return driver->Original(device, irp);
			}
		}

		return STATUS_SUCCESS;
	}
	/// <summary>
	/// ����ַת��Ϊʵ�ʵ�ַ
	/// </summary>
	/// <param name="Instruction">ָ�ʼ�ĵ�ַ</param>
	/// <param name="OffsetOffset">����ָ���ռ�ü����ֽ�</param>
	/// <param name="InstructionSize">��������ռ�ü����ֽ�</param>
	/// <returns></returns>
	PVOID ResolveRelativeAddress(_In_ PVOID Instruction, _In_ ULONG OffsetOffset, _In_ ULONG InstructionSize)
	{
		ULONG_PTR Instr = (ULONG_PTR)Instruction;
		LONG RipOffset = 0;

		RipOffset = *(PULONG)((PBYTE)Instr + OffsetOffset);

		PVOID ResolvedAddr = (PVOID)((PBYTE)Instr + InstructionSize + RipOffset);

		return ResolvedAddr;
	}

#define _DBG
#define __HOOK_DISPATCH__


	NTSTATUS SpoofNIC() {
		UNICODE_STRING pDriverName = { 0 };
		RtlInitUnicodeString(&pDriverName, L"\\Driver\\nsiproxy");

		//SwapControl(&pDriverName, NsiControl, NsiControlOriginal);


		PVOID base = Utils::GetModuleBase("ndis.sys");
		if (!base) {
			err("Failed to get ndis.sys !\n");
			return STATUS_SUCCESS;
		}

		log("ndis.sys Base:0x%llp\n", base);


		/*
			build number:22h2
			// ��һ�� ndisReferenceFilterByHandle + 0x2b
			ndis!ndisReferenceFilterByHandle+0x2b ->ndis!ndisGlobalFilterList

			fffff805`650194b3 488bf9          mov     rdi,rcx
			fffff805`650194b6 33db            xor     ebx,ebx
			fffff805`650194b8 488d0d09b60700  lea     rcx,[ndis!ndisGlobalFilterListLock (fffff805`65094ac8)]
			fffff805`650194bf 4c8b1522a40800  mov     r10,qword ptr [ndis!_imp_KeAcquireSpinLockRaiseToDpc (fffff805`650a38e8)]
			fffff805`650194c6 e8054440fa      call    nt!KeAcquireSpinLockRaiseToDpc (fffff805`5f41d8d0)
			fffff805`650194cb 408af0          mov     sil,al
			fffff805`650194ce 488b0543b00700  mov     rax,qword ptr [ndis!ndisGlobalFilterList (fffff805`65094518)]
		*/
		PVOID ndisGlobalFilterListPattern = Utils::FindPatternImage(base,
			"\x48\x8b\xf9\x33\xdb\x48\x8d\x0d\x00\x00\x00\x00\x4c\x8b\x15\x00\x00\x00\x00\xe8\x00\x00\x00\x00\x40\x8a\xf0", 
			"xxxxxxxx????xxx????x????xxx");
		
		if (!ndisGlobalFilterListPattern)
		{
			err("Failed to find the pattern ndisGlobalFilterListPattern\n");
			return STATUS_UNSUCCESSFUL;
		}

		log("ndisGlobalFilterList orginal:%llp\n", ndisGlobalFilterListPattern);

		PVOID ndisGlobalFilterListCall = Utils::reinterpret<PVOID>(ndisGlobalFilterListPattern, 27);
		if (!ndisGlobalFilterListCall)
		{
			err("Failed to find the ndisGlobalFilterListCall\n");
			return STATUS_UNSUCCESSFUL;
		}
		PNDIS_FILTER_BLOCK ndisGlobalFilterList = Utils::translateAddress<PNDIS_FILTER_BLOCK>(ndisGlobalFilterListCall, 7);

		
		if (ndisGlobalFilterList == nullptr)
		{
			err("Failed to find ndisGlobalFilterList !\n");
			return STATUS_SUCCESS;
		}
		log("ndisGlobalFilterList:0x%llp\n", ndisGlobalFilterList);
		
		/*
		// ���Ǹ��ṹ��
		PDWORD ndisFilter_IfBlock = (PDWORD)Utils::FindPatternImage(base,
			"\x48\x85\xff\x0F\x84\x00\x00\x00\x00\x4C\x8B\xA7\x00\x00\x00\x00", "xxxxx????xxx????");

	#ifdef _DBG
		Log::Print("ndisFilter_IfBlock Base:0x%llp\n", ndisFilter_IfBlock);
	#endif

		return ;
		if (ndisFilter_IfBlock == NULL) {
			Log::Print("! failed to find ndisFilter_IfBlock !\n");
			return;
		}
		*/
		/*
		fffff803`65bfa000 4885ff          test    rdi,rdi
		fffff803`65bfa003 0f8421360400    je      ndis!ndisNsiEnumerateAllInterfaceInformation+0x43d3a (fffff803`65c3d62a)
		fffff803`65bfa009 4c8ba7b8020000  mov     r12,qword ptr [rdi+2B8h] <- ���ƫ��0x2b8
		*/
		// �������ʵ���Ͼ��ǽṹ�������ƫ�� _NDIS_FILTER_BLOCK->ifBlock
		DWORD ndisFilter_IfBlock_offset = 0x2b8; // win10 22h2



#ifdef _DBG
		log("ndisGlobalFilterList Base:0x%llp, ndisFilter_IfBlock_offset: 0x%lx\n", ndisGlobalFilterList, ndisFilter_IfBlock_offset);
#endif

		/*
		 *  ndisDummyIrpHandler
		 *
		 *  fffff804`87a35da0 488bc4          mov     rax,rsp
			fffff804`87a35da3 48895808        mov     qword ptr [rax+8],rbx
			fffff804`87a35da7 48896810        mov     qword ptr [rax+10h],rbp
			fffff804`87a35dab 48897018        mov     qword ptr [rax+18h],rsi
			fffff804`87a35daf 48897820        mov     qword ptr [rax+20h],rdi
			fffff804`87a35db3 4157            push    r15
			fffff804`87a35db5 4883ec40        sub     rsp,40h
			fffff804`87a35db9 488b5940        mov     rbx,qword ptr [rcx+40h]


		 * M$ was so kind to have this function in there
		 */
		PVOID ndisDummyIrpHandler = Utils::FindPatternImage(base,
			"\x48\x8b\xc4\x48\x89\x58\x00\x48\x89\x68\x00\x48\x89\x70\x00\x48\x89\x78\x00\x41\x57\x48\x83\xec",
			"xxxxxx?xxx?xxx?xxx?xxxxx");
		if (!ndisDummyIrpHandler) {
			err("failed to get ndisDummyIrpHandler!\n");
			return STATUS_SUCCESS;
		}
		log("ndisDummyIrpHandler Base: 0x%llp!\n", ndisDummyIrpHandler);


		//return ;

		DWORD count = 0;
		for (PNDIS_FILTER_BLOCK filter = *(PNDIS_FILTER_BLOCK*)ndisGlobalFilterList; filter; filter = filter->NextFilter) {

			log("filter Addr:0x%llp\n", filter);
			PNDIS_IF_BLOCK block = *(PNDIS_IF_BLOCK*)((PBYTE)filter + ndisFilter_IfBlock_offset);
			if (block == NULL)
			{
				if (filter == filter->NextFilter) break;
				continue;
			}

			log("block:0x%llp\n", block);

			PWCHAR InstanceName = (PWCHAR)SafeCopy(filter->FilterInstanceName->Buffer, MAX_PATH);
			if (InstanceName == NULL) {
				err("failed to copy buffer. Line: %d\n", __LINE__);
				if (filter == filter->NextFilter) break;
				continue;
			}
			log("InstanceName: %ws\n", InstanceName);

			WCHAR adapter[MAX_PATH] = { 0 };
			swprintf(adapter, L"\\Device\\%ws", TrimGUID(InstanceName, MAX_PATH / 2));
			ExFreePool(InstanceName);

			log("found NIC %ws\n", adapter);

			UNICODE_STRING name = { 0 };
			RtlInitUnicodeString(&name, adapter);

			PFILE_OBJECT file = 0;
			PDEVICE_OBJECT device = 0;

			NTSTATUS status = IoGetDeviceObjectPointer(&name, FILE_READ_DATA, &file, &device);
			if (!NT_SUCCESS(status)) {
				err("! failed to get %wZ: %p !Line:%d\n", &name, status, __LINE__);
				if (filter == filter->NextFilter) break;
				continue;
			}
			log("Success to GetDeviceObjectPointer: 0x%llp, Name:%ws\n", device, name.Buffer);

			PDRIVER_OBJECT driver = device->DriverObject;
			if (driver == NULL)
			{
				err("failed to get the Driver Object\n");
				if (filter == filter->NextFilter) break;
				continue;
			}
			log("Success to Get driver Object: 0x%llp !\n", driver);



			BOOL exists = FALSE;
			for (DWORD i = 0; i < NICs.Length; ++i) {
				if (NICs.Drivers[i].DriverObject == driver) {
					exists = TRUE;
					log("Success to find driver:0x%llp [%d]!\n", NICs.Drivers[i].DriverObject, i);
					break;
				}
			}



			if (exists) {
				log("%wZ already swapped\n", &driver->DriverName);
			}
			else {
				PNIC_DRIVER nic = &NICs.Drivers[NICs.Length];
				nic->DriverObject = driver;

#ifdef __HOOK_DISPATCH_CUSTOM__
				Utils::AppendSwap(&driver->DriverName, &driver->MajorFunction[IRP_MJ_DEVICE_CONTROL], NICControl, nic->Original);
#else 
				Utils::AppendSwap(&driver->DriverName, &driver->MajorFunction[IRP_MJ_DEVICE_CONTROL], ndisDummyIrpHandler, nic->Original);
#endif
				++NICs.Length;
			}


			// Indirectly dereferences device object
			ObDereferenceObject(file);


			// Current MAC
			PIF_PHYSICAL_ADDRESS_LH addr = &block->ifPhysAddress;
			Utils::SpoofBuffer(SEED, addr->Address, addr->Length);
			addr = &block->PermanentPhysAddress;
			Utils::SpoofBuffer(SEED, addr->Address, addr->Length);

			++count;

		}

		log("handled %d MACs\n", count);

		return STATUS_SUCCESS;
	}
};