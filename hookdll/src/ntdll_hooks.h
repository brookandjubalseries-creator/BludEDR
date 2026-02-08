/*
 * BludEDR - ntdll_hooks.h
 * Critical ntdll hook declarations
 */

#pragma once

#include "../inc/hookdll.h"

/* ============================================================================
 * Original function pointers (filled by InstallHook)
 * ============================================================================ */
extern pfnNtAllocateVirtualMemory   g_pOrigNtAllocateVirtualMemory;
extern pfnNtProtectVirtualMemory    g_pOrigNtProtectVirtualMemory;
extern pfnNtWriteVirtualMemory      g_pOrigNtWriteVirtualMemory;
extern pfnNtCreateThreadEx          g_pOrigNtCreateThreadEx;
extern pfnNtMapViewOfSection        g_pOrigNtMapViewOfSection;
extern pfnNtQueueApcThread          g_pOrigNtQueueApcThread;

/* ============================================================================
 * Detour function declarations
 * ============================================================================ */
NTSTATUS NTAPI Detour_NtAllocateVirtualMemory(
    HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits,
    PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);

NTSTATUS NTAPI Detour_NtProtectVirtualMemory(
    HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize,
    ULONG NewProtect, PULONG OldProtect);

NTSTATUS NTAPI Detour_NtWriteVirtualMemory(
    HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer,
    SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten);

NTSTATUS NTAPI Detour_NtCreateThreadEx(
    PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes,
    HANDLE ProcessHandle, PVOID StartRoutine, PVOID Argument,
    ULONG CreateFlags, SIZE_T ZeroBits, SIZE_T StackSize,
    SIZE_T MaximumStackSize, PVOID AttributeList);

NTSTATUS NTAPI Detour_NtMapViewOfSection(
    HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress,
    ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize, ULONG InheritDisposition, ULONG AllocationType,
    ULONG Win32Protect);

NTSTATUS NTAPI Detour_NtQueueApcThread(
    HANDLE ThreadHandle, PVOID ApcRoutine, PVOID ApcArgument1,
    PVOID ApcArgument2, PVOID ApcArgument3);
