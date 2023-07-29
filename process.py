import os
os.chdir(os.environ['USERPROFILE']+"\\"+"Area")
import ctypes
import locale
import logging
import os

import exception
import ressources.advapi32
import ressources.kernel32
import ressources.psapi
import ressources.structure


logger = logging.getLogger(__name__)


def get_python_dll(version):

    current_process_id = os.getpid()
    current_process_handle = process.open(current_process_id)
    for module in process.enum_process_module(current_process_handle):
        if module.name == version:
            return module.filename


def inject_dll(handle, filepath):

    filepath_address = ressources.kernel32.VirtualAllocEx(
        handle,
        0,
        len(filepath),
        ressources.structure.MEMORY_STATE.MEM_COMMIT.value | ressources.structure.MEMORY_STATE.MEM_RESERVE.value,
        ressources.structure.MEMORY_PROTECTION.PAGE_EXECUTE_READWRITE.value
    )
    ressources.kernel32.WriteProcessMemory(handle, filepath_address, filepath, len(filepath), None)
    kernel32_handle = ressources.kernel32.GetModuleHandleW("kernel32.dll")
    load_library_a_address = ressources.kernel32.GetProcAddress(kernel32_handle, b"LoadLibraryA")
    thread_h = ressources.kernel32.CreateRemoteThread(
        handle, None, 0, load_library_a_address, filepath_address, 0, None
    )
    ressources.kernel32.WaitForSingleObject(thread_h, -1)
    ressources.kernel32.VirtualFreeEx(
        handle, filepath_address, len(filepath), ressources.structure.MEMORY_STATE.MEM_RELEASE.value
    )
    dll_name = os.path.basename(filepath)
    dll_name = dll_name.decode('ascii')
    module_address = ressources.kernel32.GetModuleHandleW(dll_name)
    return module_address


def get_luid(name):

    luid = ressources.structure.LUID()
    res = ressources.advapi32.LookupPrivilegeValue(None, name, luid)
    if not res > 0:
        raise RuntimeError("Couldn't lookup privilege value")
    return luid


def get_process_token():

    token = ctypes.c_void_p()
    res = ressources.advapi32.OpenProcessToken(
        ctypes.windll.kernel32.GetCurrentProcess(),
        ressources.structure.TOKEN.TOKEN_ALL_ACCESS,
        token
    )
    if not res > 0:
        raise RuntimeError("Couldn't get process token")
    return token


def set_debug_privilege(lpszPrivilege, bEnablePrivilege):

    # create a space in memory for a TOKEN_PRIVILEGES structure
    #  with one element
    size = ctypes.sizeof(ressources.structure.TOKEN_PRIVILEGES)
    size += ctypes.sizeof(ressources.structure.LUID_AND_ATTRIBUTES)
    buffer = ctypes.create_string_buffer(size)

    tp = ctypes.cast(buffer, ctypes.POINTER(ressources.structure.TOKEN_PRIVILEGES)).contents
    tp.count = 1
    tp.get_array()[0].LUID = get_luid(lpszPrivilege)
    tp.get_array()[0].Attributes = (
        ressources.structure.SE_TOKEN_PRIVILEGE.SE_PRIVILEGE_ENABLED if bEnablePrivilege else 0
    )
    token = get_process_token()
    res = ressources.advapi32.AdjustTokenPrivileges(token, False, tp, 0, None, None)
    if res == 0:
        raise RuntimeError("AdjustTokenPrivileges error: 0x%08x\n" % ctypes.GetLastError())

    ERROR_NOT_ALL_ASSIGNED = 1300
    return ctypes.windll.kernel32.GetLastError() != ERROR_NOT_ALL_ASSIGNED


def base_module(handle):

    hModules = (ctypes.c_void_p * 1024)()
    process_module_success = ressources.psapi.EnumProcessModulesEx(
        handle,
        ctypes.byref(hModules),
        ctypes.sizeof(hModules),
        ctypes.byref(ctypes.c_ulong()),
        ressources.structure.EnumProcessModuleEX.LIST_MODULES_ALL
    )
    if not process_module_success:
        return  # xxx
    module_info = ressources.structure.MODULEINFO(handle)
    ressources.psapi.GetModuleInformation(
        handle,
        ctypes.c_void_p(hModules[0]),
        ctypes.byref(module_info),
        ctypes.sizeof(module_info)
    )
    return module_info


def open(process_id, debug=True, process_access=None):

    if not process_access:
        process_access = ressources.structure.PROCESS.PROCESS_ALL_ACCESS.value
    if debug:
        set_debug_privilege('SeDebugPrivilege', True)
    process_handle = ressources.kernel32.OpenProcess(process_access, False, process_id)
    return process_handle


def open_main_thread(process_id):

    threads = enum_process_thread(process_id)
    threads = sorted(threads, key=lambda t32: t32.creation_time)

    if not threads:
        return  # todo: raise exception

    main_thread = threads[0]
    thread_handle = open_thread(main_thread.th32ThreadID)
    return thread_handle


# TODO: impl enum for thread access levels
def open_thread(thread_id, thread_access=None):

    if thread_access is None:
        thread_access = 0x001F03FF
    thread_handle = ressources.kernel32.OpenThread(thread_access, 0, thread_id)
    return thread_handle


def close_handle(handle):

    if not handle:
        return
    success = ressources.kernel32.CloseHandle(handle)
    return success != 0


def list_processes():

    SNAPPROCESS = 0x00000002
    hSnap = ressources.kernel32.CreateToolhelp32Snapshot(SNAPPROCESS, 0)
    process_entry = ressources.structure.ProcessEntry32()
    process_entry.dwSize = ctypes.sizeof(process_entry)
    p32 = ressources.kernel32.Process32First(hSnap, ctypes.byref(process_entry))
    if p32:
        yield process_entry
    while p32:
        yield process_entry
        p32 = ressources.kernel32.Process32Next(hSnap, ctypes.byref(process_entry))
    ressources.kernel32.CloseHandle(hSnap)


def process_from_name(
    name: str,
    exact_match: bool = False,
    ignore_case: bool = True,
):


    if ignore_case:
        name = name.lower()

    processes = list_processes()
    for process in processes:
        process_name = process.szExeFile.decode(locale.getpreferredencoding())

        if ignore_case:
            process_name = process_name.lower()

        if exact_match:
            if process_name == name:
                return process
        else:
            if name in process_name:
                return process


def process_from_id(process_id):

    processes = list_processes()
    for process in processes:
        if process_id == process.th32ProcessID:
            return process


def module_from_name(process_handle, module_name):

    module_name = module_name.lower()
    modules = enum_process_module(process_handle)
    for module in modules:
        if module.name.lower() == module_name:
            return module


def enum_process_thread(process_id):

    TH32CS_SNAPTHREAD = 0x00000004
    hSnap = ressources.kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
    thread_entry = ressources.structure.ThreadEntry32()
    ret = ressources.kernel32.Thread32First(hSnap, ctypes.byref(thread_entry))

    if not ret:
        raise exception.memError('Could not get Thread32First')

    while ret:
        if thread_entry.th32OwnerProcessID == process_id:
            yield thread_entry
        ret = ressources.kernel32.Thread32Next(hSnap, ctypes.byref(thread_entry))
    ressources.kernel32.CloseHandle(hSnap)


def enum_process_module(handle):

    hModules = (ctypes.c_void_p * 1024)()
    process_module_success = ressources.psapi.EnumProcessModulesEx(
        handle,
        ctypes.byref(hModules),
        ctypes.sizeof(hModules),
        ctypes.byref(ctypes.c_ulong()),
        ressources.structure.EnumProcessModuleEX.LIST_MODULES_ALL
    )
    if process_module_success:
        hModules = iter(m for m in hModules if m)
        for hModule in hModules:
            module_info = ressources.structure.MODULEINFO(handle)
            ressources.psapi.GetModuleInformation(
                handle,
                ctypes.c_void_p(hModule),
                ctypes.byref(module_info),
                ctypes.sizeof(module_info)
            )
            yield module_info


# TODO: should this be named is_wow64?
def is_64_bit(handle):

    Wow64Process = ctypes.c_long()
    ressources.kernel32.IsWow64Process(handle, ctypes.byref(Wow64Process))
    return bool(Wow64Process.value)
