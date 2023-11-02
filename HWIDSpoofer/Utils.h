#pragma once
#include <ntifs.h>
#include <windef.h>


namespace Utils
{
	PVOID GetModuleBase(const char* moduleName);
	bool CheckMask(const char* base, const char* pattern, const char* mask);
	PVOID FindPattern(PVOID base, int length, const char* pattern, const char* mask);
	PVOID FindPatternImage(PVOID base, const char* pattern, const char* mask);
	void RandomText(char* text, const int length);
	VOID SpoofBuffer(DWORD seed, PBYTE buffer, DWORD length);

	BOOL SwapControl(PUNICODE_STRING pDriverName, PVOID hook, PVOID original);

	BOOL AppendSwap(PUNICODE_STRING pDriverName, PVOID pSwap, PVOID hook, PVOID original);

	

#define AdjustOffset(OriAddr, Offset) ((PBYTE)OriAddr + Offset)

	// �����OriAddrָ������һ��Offset��ƫ�ƣ��������½���ΪT����
	template<class T>
	T reinterpret(PVOID OriAddr, DWORD Offset)
	{
		return reinterpret_cast<T>(AdjustOffset(OriAddr, Offset));
	}

	// �����ú����ĵ�ַ��ת��Ϊ������ַ
	///
	/// base : ���ú�������ʼ��ַ(call)
	/// totalLen: ��ָ���ܳ��� = ָ�� + ��ַ
	///
	template<class T>
	T translateAddress(PVOID base, int totalLen)
	{
		int instrLen = totalLen - 4;
		__try {
			
			//ProbeForRead((PBYTE)base + instrLen, sizeof(LONG), sizeof(UCHAR));

			return (T)((PBYTE)base + totalLen + *((PLONG)((PBYTE)base + instrLen)));
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			return nullptr;
		}
	}
};