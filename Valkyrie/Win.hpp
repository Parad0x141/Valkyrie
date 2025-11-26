#pragma once
#include "Common.hpp"

constexpr ULONG MAX_IMG_NOTIFY = 64;

constexpr auto SystemExtendedHandleInformation = static_cast<SYSTEM_INFORMATION_CLASS>(64);



#pragma pack(push, 1)
typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX
{
    PVOID  Object;                 // 0x00
    ULONG_PTR UniqueProcessId;     // 0x08
    ULONG_PTR HandleValue;         // 0x10
    ULONG  GrantedAccess;          // 0x18
    USHORT CreatorBackTraceIndex;  // 0x1C
    USHORT ObjectTypeIndex;        // 0x1E
    ULONG  HandleAttributes;       // 0x20
    ULONG  Reserved;               // 0x24
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX
{
    ULONG_PTR NumberOfHandles;     // 0x00
    ULONG_PTR Reserved;            // 0x08
    SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1]; // 0x10
} SYSTEM_HANDLE_INFORMATION_EX, * PSYSTEM_HANDLE_INFORMATION_EX;
#pragma pack(pop)

struct EX_RUNDOWN_REF { ULONG_PTR Count; };

typedef struct _RTL_BALANCED_LINKS 
{
    struct _RTL_BALANCED_LINKS* Parent;
    struct _RTL_BALANCED_LINKS* LeftChild;
    struct _RTL_BALANCED_LINKS* RightChild;
    CHAR Balance;
    UCHAR Reserved[3];
} RTL_BALANCED_LINKS, * PRTL_BALANCED_LINKS;

typedef struct _RTL_AVL_TABLE 
{
    RTL_BALANCED_LINKS BalancedRoot;
    PVOID OrderedPointer;
    ULONG WhichOrderedElement;
    ULONG NumberGenericTableElements;
    ULONG DepthOfTree;
    PVOID RestartKey;
    ULONG DeleteCount;
    PVOID CompareRoutine;
    PVOID AllocateRoutine;
    PVOID FreeRoutine;
    PVOID TableContext;
} RTL_AVL_TABLE, * PRTL_AVL_TABLE;




typedef struct _PiDDBCacheEntry
{
    LIST_ENTRY		List;
    UNICODE_STRING	DriverName;
    ULONG			TimeDateStamp;
    NTSTATUS		LoadStatus;
    char			_0x0028[16];
} PiDDBCacheEntry, * NPiDDBCacheEntry;




typedef struct _HashBucketEntry
{
    struct _HashBucketEntry* Next;
    UNICODE_STRING DriverName;
    ULONG CertHash[5];
} HashBucketEntry, * PHashBucketEntry;