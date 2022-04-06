#pragma once
 
#define NT_SUCCESS(Status) ((NTSTATUS)(status) >= 0)
template <class T>
struct _LIST_ENTRY_T
{
    T Flink;
    T Blink;
};

template <class T>
struct _UNICODE_STRING_T
{
    union
    {
        struct
        {
            WORD Length;
            WORD MaximumLength;
        };
        T dummy;
    };
    T Buffer;
};
template <class T>
struct _PEB_LDR_DATA_T
{
    DWORD Length;
    DWORD Initialized;
    T SsHandle;
    _LIST_ENTRY_T<T> InLoadOrderModuleList;
    _LIST_ENTRY_T<T> InMemoryOrderModuleList;
    _LIST_ENTRY_T<T> InInitializationOrderModuleList;
    T EntryInProgress;
    DWORD ShutdownInProgress;
    T ShutdownThreadId;

};
typedef _PEB_LDR_DATA_T<DWORD64> PEB_LDR_DATA64;

template <class T, class NGF, int A>
struct _PEB_T
{
    union
    {
        struct
        {
            BYTE InheritedAddressSpace;
            BYTE ReadImageFileExecOptions;
            BYTE BeingDebugged;
            BYTE BitField;
        };
        T dummy01;
    };
    T Mutant;
    T ImageBaseAddress;
    T Ldr;
    T ProcessParameters;
    T SubSystemData;
    T ProcessHeap;
    T FastPebLock;
    T AtlThunkSListPtr;
    T IFEOKey;
    T CrossProcessFlags;
    T UserSharedInfoPtr;
    DWORD SystemReserved;
    DWORD AtlThunkSListPtr32;
    T ApiSetMap;
    T TlsExpansionCounter;
    T TlsBitmap;
    DWORD TlsBitmapBits[2];
    T ReadOnlySharedMemoryBase;
    T HotpatchInformation;
    T ReadOnlyStaticServerData;
    T AnsiCodePageData;
    T OemCodePageData;
    T UnicodeCaseTableData;
    DWORD NumberOfProcessors;
    union
    {
        DWORD NtGlobalFlag;
        NGF dummy02;
    };
    LARGE_INTEGER CriticalSectionTimeout;
    T HeapSegmentReserve;
    T HeapSegmentCommit;
    T HeapDeCommitTotalFreeThreshold;
    T HeapDeCommitFreeBlockThreshold;
    DWORD NumberOfHeaps;
    DWORD MaximumNumberOfHeaps;
    T ProcessHeaps;
    T GdiSharedHandleTable;
    T ProcessStarterHelper;
    T GdiDCAttributeList;
    T LoaderLock;
    DWORD OSMajorVersion;
    DWORD OSMinorVersion;
    WORD OSBuildNumber;
    WORD OSCSDVersion;
    DWORD OSPlatformId;
    DWORD ImageSubsystem;
    DWORD ImageSubsystemMajorVersion;
    T ImageSubsystemMinorVersion;
    T ActiveProcessAffinityMask;
    T GdiHandleBuffer[A];
    T PostProcessInitRoutine;
    T TlsExpansionBitmap;
    DWORD TlsExpansionBitmapBits[32];
    T SessionId;
    ULARGE_INTEGER AppCompatFlags;
    ULARGE_INTEGER AppCompatFlagsUser;
    T pShimData;
    T AppCompatInfo;
    _UNICODE_STRING_T<T> CSDVersion;
    T ActivationContextData;
    T ProcessAssemblyStorageMap;
    T SystemDefaultActivationContextData;
    T SystemAssemblyStorageMap;
    T MinimumStackCommit;
    T FlsCallback;
    _LIST_ENTRY_T<T> FlsListHead;
    T FlsBitmap;
    DWORD FlsBitmapBits[4];
    T FlsHighIndex;
    T WerRegistrationData;
    T WerShipAssertPtr;
    T pContextData;
    T pImageHeaderHash;
    T TracingFlags;
};


#define GDI_HANDLE_BUFFER_SIZE32 34
#define GDI_HANDLE_BUFFER_SIZE64 60

#ifndef _WIN64
#define GDI_HANDLE_BUFFER_SIZE GDI_HANDLE_BUFFER_SIZE32
#else
#define GDI_HANDLE_BUFFER_SIZE GDI_HANDLE_BUFFER_SIZE64
#endif
typedef LONG KPRIORITY;
typedef ULONG GDI_HANDLE_BUFFER[GDI_HANDLE_BUFFER_SIZE];
typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    _Field_size_bytes_part_(MaximumLength, Length) PWCH Buffer;
} UNICODE_STRING, * PUNICODE_STRING;
// symbols
typedef struct _PEB
{
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    union
    {
        BOOLEAN BitField;
        struct
        {
            BOOLEAN ImageUsesLargePages : 1;
            BOOLEAN IsProtectedProcess : 1;
            BOOLEAN IsImageDynamicallyRelocated : 1;
            BOOLEAN SkipPatchingUser32Forwarders : 1;
            BOOLEAN IsPackagedProcess : 1;
            BOOLEAN IsAppContainer : 1;
            BOOLEAN IsProtectedProcessLight : 1;
            BOOLEAN IsLongPathAwareProcess : 1;
        };
    };

    HANDLE Mutant;

    PVOID ImageBaseAddress;
    PVOID Ldr;
    PVOID ProcessParameters;
    PVOID SubSystemData;
    PVOID ProcessHeap;
    PRTL_CRITICAL_SECTION FastPebLock;
    PSLIST_HEADER AtlThunkSListPtr;
    PVOID IFEOKey;

    union
    {
        ULONG CrossProcessFlags;
        struct
        {
            ULONG ProcessInJob : 1;
            ULONG ProcessInitializing : 1;
            ULONG ProcessUsingVEH : 1;
            ULONG ProcessUsingVCH : 1;
            ULONG ProcessUsingFTH : 1;
            ULONG ProcessPreviouslyThrottled : 1;
            ULONG ProcessCurrentlyThrottled : 1;
            ULONG ProcessImagesHotPatched : 1; // REDSTONE5
            ULONG ReservedBits0 : 24;
        };
    };
    union
    {
        PVOID KernelCallbackTable;
        PVOID UserSharedInfoPtr;
    };
    ULONG SystemReserved;
    ULONG AtlThunkSListPtr32;
    PVOID ApiSetMap;
    ULONG TlsExpansionCounter;
    PVOID TlsBitmap;
    ULONG TlsBitmapBits[2];

    PVOID ReadOnlySharedMemoryBase;
    PVOID SharedData; // HotpatchInformation
    PVOID* ReadOnlyStaticServerData;

    PVOID AnsiCodePageData; // PCPTABLEINFO
    PVOID OemCodePageData; // PCPTABLEINFO
    PVOID UnicodeCaseTableData; // PNLSTABLEINFO

    ULONG NumberOfProcessors;
    ULONG NtGlobalFlag;

    ULARGE_INTEGER CriticalSectionTimeout;
    SIZE_T HeapSegmentReserve;
    SIZE_T HeapSegmentCommit;
    SIZE_T HeapDeCommitTotalFreeThreshold;
    SIZE_T HeapDeCommitFreeBlockThreshold;

    ULONG NumberOfHeaps;
    ULONG MaximumNumberOfHeaps;
    PVOID* ProcessHeaps; // PHEAP

    PVOID GdiSharedHandleTable;
    PVOID ProcessStarterHelper;
    ULONG GdiDCAttributeList;

    PRTL_CRITICAL_SECTION LoaderLock;

    ULONG OSMajorVersion;
    ULONG OSMinorVersion;
    USHORT OSBuildNumber;
    USHORT OSCSDVersion;
    ULONG OSPlatformId;
    ULONG ImageSubsystem;
    ULONG ImageSubsystemMajorVersion;
    ULONG ImageSubsystemMinorVersion;
    ULONG_PTR ActiveProcessAffinityMask;
    GDI_HANDLE_BUFFER GdiHandleBuffer;
    PVOID PostProcessInitRoutine;

    PVOID TlsExpansionBitmap;
    ULONG TlsExpansionBitmapBits[32];

    ULONG SessionId;

    ULARGE_INTEGER AppCompatFlags;
    ULARGE_INTEGER AppCompatFlagsUser;
    PVOID pShimData;
    PVOID AppCompatInfo; // APPCOMPAT_EXE_DATA

    UNICODE_STRING CSDVersion;

    PVOID ActivationContextData; // ACTIVATION_CONTEXT_DATA
    PVOID ProcessAssemblyStorageMap; // ASSEMBLY_STORAGE_MAP
    PVOID SystemDefaultActivationContextData; // ACTIVATION_CONTEXT_DATA
    PVOID SystemAssemblyStorageMap; // ASSEMBLY_STORAGE_MAP

    SIZE_T MinimumStackCommit;

    PVOID SparePointers[4]; // 19H1 (previously FlsCallback to FlsHighIndex)
    ULONG SpareUlongs[5]; // 19H1
    //PVOID* FlsCallback;
    //LIST_ENTRY FlsListHead;
    //PVOID FlsBitmap;
    //ULONG FlsBitmapBits[FLS_MAXIMUM_AVAILABLE / (sizeof(ULONG) * 8)];
    //ULONG FlsHighIndex;

    PVOID WerRegistrationData;
    PVOID WerShipAssertPtr;
    PVOID pUnused; // pContextData
    PVOID pImageHeaderHash;
    union
    {
        ULONG TracingFlags;
        struct
        {
            ULONG HeapTracingEnabled : 1;
            ULONG CritSecTracingEnabled : 1;
            ULONG LibLoaderTracingEnabled : 1;
            ULONG SpareTracingBits : 29;
        };
    };
    ULONGLONG CsrServerReadOnlySharedMemoryBase;
    PRTL_CRITICAL_SECTION TppWorkerpListLock;
    LIST_ENTRY TppWorkerpList;
    PVOID WaitOnAddressHashTable[128];
    PVOID TelemetryCoverageHeader; // REDSTONE3
    ULONG CloudFileFlags;
    ULONG CloudFileDiagFlags; // REDSTONE4
    CHAR PlaceholderCompatibilityMode;
    CHAR PlaceholderCompatibilityModeReserved[7];
    struct _LEAP_SECOND_DATA* LeapSecondData; // REDSTONE5
    union
    {
        ULONG LeapSecondFlags;
        struct
        {
            ULONG SixtySecondEnabled : 1;
            ULONG Reserved : 31;
        };
    };
    ULONG NtGlobalFlag2;
} PEB, * PPEB;

template <class T>
struct _LDR_DATA_TABLE_ENTRY_T
{
    _LIST_ENTRY_T<T> InLoadOrderLinks;
    _LIST_ENTRY_T<T> InMemoryOrderLinks;
    _LIST_ENTRY_T<T> InInitializationOrderLinks;
    T DllBase;
    T EntryPoint;
    union
    {
        DWORD SizeOfImage;
        T dummy01;
    };
    _UNICODE_STRING_T<T> FullDllName;
    _UNICODE_STRING_T<T> BaseDllName;
    DWORD Flags;
    WORD LoadCount;
    WORD TlsIndex;
    union
    {
        _LIST_ENTRY_T<T> HashLinks;
        struct
        {
            T SectionPointer;
            T CheckSum;
        };
    };
    union
    {
        T LoadedImports;
        DWORD TimeDateStamp;
    };
    T EntryPointActivationContext;
    T PatchInformation;
    _LIST_ENTRY_T<T> ForwarderLinks;
    _LIST_ENTRY_T<T> ServiceTagLinks;
    _LIST_ENTRY_T<T> StaticLinks;
    T ContextInformation;
    T OriginalBase;
    _LARGE_INTEGER LoadTime;
};


typedef _LDR_DATA_TABLE_ENTRY_T<DWORD64> LDR_DATA_TABLE_ENTRY64;
typedef _PEB_LDR_DATA_T<DWORD> PEB_LDR_DATA32;
typedef _PEB_T<DWORD64, DWORD, 30> PEB64;
#define PTR_ADD_OFFSET(Pointer, Offset) ((PVOID)((ULONG_PTR)(Pointer) + (ULONG_PTR)(Offset)))
#define FIELD_OFFSET(type, field)    ((LONG)(LONG_PTR)&(((type *)0)->field))

#define PTR_ADD_OFFSET64(Pointer,Offset) ((ULONG64)((ULONG64)(Pointer) + (ULONG_PTR)(Offset)))
#define FIELD_OFFSET64(type, field)    ((LONG)(LONG64)&(((type *)0)->field))

typedef LONG(WINAPI* TypeNtQueryInformationProcess)(HANDLE	ProcessHandle, UINT	ProcessInformationClass, PVOID	ProcessInformation, ULONG	ProcessInformationLength, PULONG	ReturnLength);
typedef BOOL(WINAPI* QueryFullProcessImageNameAType)(HANDLE hProcess, DWORD  dwFlags, LPSTR  lpExeName, PDWORD lpdwSize);
typedef NTSTATUS(NTAPI* fnNtWow64ReadVirtualMemory64)(IN  HANDLE   ProcessHandle, IN  ULONG64  BaseAddress, OUT PVOID    Buffer, IN  ULONG64  BufferLength, OUT PULONG64 ReturnLength OPTIONAL);
typedef BOOL(WINAPI* ReadProcessMemoryType)(HANDLE  hProcess, LPCVOID lpBaseAddress, LPVOID  lpBuffer, SIZE_T  nSize, SIZE_T* lpNumberOfBytesRead);
typedef struct _PROCESS_BASIC_INFORMATION
{
    NTSTATUS ExitStatus;
    PPEB PebBaseAddress;
    ULONG_PTR AffinityMask;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION, * PPROCESS_BASIC_INFORMATION;


template<typename T>
struct _PROCESS_BASIC_INFORMATION_T
{
    NTSTATUS ExitStatus;
    uint32_t    Reserved0;
    T	     PebBaseAddress;
    T	     AffinityMask;
    LONG	 BasePriority;
    ULONG	 Reserved1;
    T	     uUniqueProcessId;
    T	     uInheritedFromUniqueProcessId;
};
union reg64
{
    DWORD64 v;
    DWORD dw[2];
};

#define HOOK_DATA_LEN   4
#define FREE(p) do{\
if(p)free(p);\
p=nullptr;\
}while(false)

#define ALLOC(size,pOut) do{pOut=(void*)malloc(size);\
if(pOut){memset(pOut,0,size);}\
}while(false)

class CCheckTextSectionDiff
{
public:
    CCheckTextSectionDiff(DWORD pid) :m_pid(pid), m_hProc(NULL),m_pFileCode(NULL),m_pMemCode(NULL), m_FileCodeSize(0), m_bFuncsImport(FALSE), m_TargetWow64(FALSE)\
        ,pfnNtWowQueryInformationProcess64(NULL), pfnQueryFullProcessImageNameA(NULL), pfnNtReadProcessMemoryWoW64(NULL), pfnNtQueryInformationProcess(NULL), pfnReadProcessMemory(NULL)
    {
        m_hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);

        // Detect x86 OS
        SYSTEM_INFO info = { { 0 } };
        GetNativeSystemInfo(&info);
        if (info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL)
        {
            m_TargetWow64 = FALSE;
        }
        else
        {
            BOOL bTargetWow = FALSE;
            IsWow64Process(m_hProc, &bTargetWow);
            m_TargetWow64 = !bTargetWow;
        }
        if (m_TargetWow64)
        {
            PVOID oldValue = NULL;
            Wow64DisableWow64FsRedirection(&oldValue);
        }
        ImportFunctions();
    }
    ~CCheckTextSectionDiff()
    {
        if (m_hProc)     { ::CloseHandle(m_hProc);m_hProc = NULL; }
        if (m_pFileCode) { free(m_pFileCode);m_pFileCode = NULL; }
        if (m_pMemCode)  { free(m_pMemCode); m_pMemCode = NULL;  }
    }

    NTSTATUS LoadTextCode()
    {
        NTSTATUS status;
        if (m_TargetWow64)
        {
            status = ReadMemTextCodeWoW64();
            if (!NT_SUCCESS(status)) {
                printf("ReadMemTextCodeWoW64 falied,0x%x \n", status);
            }
            status = ReadFileTextCodeWow64();
            if (!NT_SUCCESS(status)) {
                printf("ReadFileTextCodeWow64 falied,0x%x \n", status);
            }
        }
        else
        {
            status = ReadMemTextCode();
            if (!NT_SUCCESS(status)) {
                printf("ReadMemTextCode falied,0x%x \n", status);
            }
            status = ReadFileTextCode();
            if (!NT_SUCCESS(status)) {
                printf("ReadFileTextCode falied,0x%x \n", status);
            }
        }
        
        return status;
    }



    DWORD64 GetModuleHandle64(PEB64* peb64, const wchar_t* lpModuleName);
    void  Dump2File(const char* pDumpFile, BYTE* p, UINT64 size);
    bool  CheckDiff(const BYTE* p1, const BYTE* p2, UINT64 size, DWORD Virtualoffset);

    BYTE* FileCode()      { return m_pFileCode; }
    DWORD FileCodeSize() { return m_FileCodeSize; }

    BYTE* MemCode() { return m_pMemCode; }
    DWORD MemCodeSize() { return m_MemCodeSize; }

    DWORD VirtualOff() { return m_virtualOff; }
private:

    NTSTATUS ReadMemTextCodeByBase(DWORD imageBase,  __inout BYTE** mem, __out DWORD& memSize, __out DWORD& fileCodeSize, __out DWORD& virtualOff);
    NTSTATUS ReadMemTextCodeByBaseWow64(DWORD64 imageBase64, __inout BYTE** mem, __out DWORD& memSize, __out DWORD& fileCodeSize, __out DWORD& virtualOff);
    void getMem64(void* dstMem, DWORD64 srcMem, size_t sz);
    NTSTATUS ReadMemTextCode();
    NTSTATUS ReadMemTextCodeWoW64();

    NTSTATUS ReadFileTextCode();
    NTSTATUS ReadFileTextCodeWow64();

    BYTE* GetTextCodeLocal(CHAR* szExeFileName, DWORD& codeSize);
    BYTE* GetTextCodeLocalWoW64(CHAR* szExeFileName, DWORD& codeSize);
    uint32_t Align(uint32_t value, uint32_t element)
    {
        if (0 == element)
        {
            return value;
        }

        return value % element ? (value / element + 1) * element : (value / element) * element;
    }

    BOOL ImportFunctions()
    {
        pfnNtWowQueryInformationProcess64 = (TypeNtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWow64QueryInformationProcess64");
        pfnQueryFullProcessImageNameA = (QueryFullProcessImageNameAType)GetProcAddress(GetModuleHandleA("kernel32.dll"), "QueryFullProcessImageNameA");
        pfnNtReadProcessMemoryWoW64 = (fnNtWow64ReadVirtualMemory64)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWow64ReadVirtualMemory64");
 
        pfnNtQueryInformationProcess = (TypeNtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
        pfnReadProcessMemory = (ReadProcessMemoryType)GetProcAddress(GetModuleHandleA("kernel32.dll"), "ReadProcessMemory");

        if (!pfnNtWowQueryInformationProcess64 ||
            !pfnQueryFullProcessImageNameA ||
            !pfnNtReadProcessMemoryWoW64 ||
            !pfnNtQueryInformationProcess ||
            !pfnReadProcessMemory)
            return false;

        m_bFuncsImport = TRUE;
        return true;
        
    }
    BOOL  m_bFuncsImport;
    BOOL  m_TargetWow64;

    HANDLE m_hProc;           //目标进程句柄
    DWORD  m_pid;             //目标进程PID
    BYTE*  m_pMemCode;        //内存中的代码段信息
    BYTE*  m_pFileCode;       //文件中代码段的信息
    DWORD  m_FileCodeSize;    //待比较代码段在文件中的大小（不是内存中）
    DWORD  m_MemCodeSize;     //待比较代码段在内存中的大
    DWORD  m_virtualOff;      //内存中代码段的偏移地址

    TypeNtQueryInformationProcess pfnNtWowQueryInformationProcess64;
    QueryFullProcessImageNameAType pfnQueryFullProcessImageNameA;
    fnNtWow64ReadVirtualMemory64 pfnNtReadProcessMemoryWoW64;

    TypeNtQueryInformationProcess pfnNtQueryInformationProcess;
    ReadProcessMemoryType        pfnReadProcessMemory;
};