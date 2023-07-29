import os
os.chdir(os.environ['USERPROFILE']+"\\"+"Area")
import ctypes
import ctypes.util
import functools
import logging
import platform
import struct
import sys
import typing

import exception
import memory
import process
import ressources.kernel32
import ressources.structure
import ressources.psapi
import thread
import pattern


# Configure 's handler to the lowest level possible so everything is cached and could be later displayed
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
logger.addHandler(logging.NullHandler())


class mem(object):
    def __init__(
        self,
        process_name: typing.Union[str, int] = None,
        exact_match: bool = False,
        ignore_case: bool = True,
    ):
        self.process_id = None
        self.process_handle = None
        self.thread_handle = None
        self.is_WoW64 = None
        self.py_run_simple_string = None
        self._python_injected = None

        if process_name is not None:
            if isinstance(process_name, str):
                self.open_process_from_name(process_name, exact_match, ignore_case)
            elif isinstance(process_name, int):
                self.open_process_from_id(process_name)
            else:
                raise TypeError(
                    f"process_name must be of type int or string not {type(process_name).__name__}"
                )

        self.check_wow64()

    def check_wow64(self):
        self.is_WoW64 = process.is_64_bit(self.process_handle)

    def list_modules(self):
        modules = process.enum_process_module(self.process_handle)
        return modules

    def inject_python_interpreter(self, initsigs=1):
        def find_existing_interpreter(_python_version):
            _local_handle = ressources.kernel32.GetModuleHandleW(_python_version)
            module = process.module_from_name(self.process_handle, _python_version)

            self.py_run_simple_string = (
                module.lpBaseOfDll + (
                    ressources.kernel32.GetProcAddress(_local_handle, b'PyRun_SimpleString') - _local_handle
                )
            )
            self._python_injected = True
            logger.debug('PyRun_SimpleString loc: 0x%08x' % self.py_run_simple_string)
            return module.lpBaseOfDll

        if self._python_injected:
            return

        # find the python library
        python_version = "python{0}{1}.dll".format(sys.version_info.major, sys.version_info.minor)
        python_lib = process.get_python_dll(python_version)
        if not python_lib:
            raise exception.memError('Could not find python library')

        # Find or inject python module
        python_module = process.module_from_name(self.process_handle, python_version)
        if python_module:
            python_lib_h = find_existing_interpreter(python_version)
        else:
            python_lib_h = process.inject_dll(self.process_handle, bytes(python_lib, 'ascii'))
            if not python_lib_h:
                raise exception.memError('Inject dll failed')

        local_handle = ressources.kernel32.GetModuleHandleW(python_version)
        py_initialize_ex = (
            python_lib_h + (
                ressources.kernel32.GetProcAddress(local_handle, b'Py_InitializeEx') - local_handle
            )
        )
        self.py_run_simple_string = (
            python_lib_h + (
                ressources.kernel32.GetProcAddress(local_handle, b'PyRun_SimpleString') - local_handle
            )
        )
        if not py_initialize_ex:
            raise exception.memError('Empty py_initialize_ex')
        if not self.py_run_simple_string:
            raise exception.memError('Empty py_run_simple_string')

        param_addr = self.allocate(4)
        self.write_int(param_addr, initsigs)
        self.start_thread(py_initialize_ex, param_addr)
        self._python_injected = True

        logger.debug('Py_InitializeEx loc: 0x%08x' % py_initialize_ex)
        logger.debug('PyRun_SimpleString loc: 0x%08x' % self.py_run_simple_string)

    def inject_python_shellcode(self, shellcode):
        shellcode = shellcode.encode('ascii')
        shellcode_addr = ressources.kernel32.VirtualAllocEx(
            self.process_handle,
            None,
            len(shellcode),
            ressources.structure.MEMORY_STATE.MEM_COMMIT.value | ressources.structure.MEMORY_STATE.MEM_RESERVE.value,
            ressources.structure.MEMORY_PROTECTION.PAGE_EXECUTE_READWRITE.value
        )
        if not shellcode_addr or ctypes.get_last_error():
            raise RuntimeError('Could not allocate memory for shellcode')
        logger.debug('shellcode_addr loc: 0x%08x' % shellcode_addr)
        written = ctypes.c_ulonglong(0) if '64bit' in platform.architecture() else ctypes.c_ulong(0)
        ressources.kernel32.WriteProcessMemory(
            self.process_handle,
            shellcode_addr,
            shellcode,
            len(shellcode),
            ctypes.byref(written)
        )
        # check written
        self.start_thread(self.py_run_simple_string, shellcode_addr)

    def start_thread(self, address, params=None):
        params = params or 0
        NULL_SECURITY_ATTRIBUTES = ctypes.cast(0, ressources.structure.LPSECURITY_ATTRIBUTES)
        thread_h = ressources.kernel32.CreateRemoteThread(
            self.process_handle,
            NULL_SECURITY_ATTRIBUTES,
            0,
            address,
            params,
            0,
            ctypes.byref(ctypes.c_ulong(0))
        )
        last_error = ctypes.windll.kernel32.GetLastError()
        if last_error:
            logger.warning('Got an error in start thread, code: %s' % last_error)
        ressources.kernel32.WaitForSingleObject(thread_h, -1)
        logger.debug('New thread_id: 0x%08x' % thread_h)
        return thread_h

    def open_process_from_name(
        self,
        process_name: str,
        exact_match: bool = False,
        ignore_case: bool = True,
    ):
        if not process_name or not isinstance(process_name, str):
            raise TypeError('Invalid argument: {}'.format(process_name))

        if not isinstance(exact_match, bool):
            raise TypeError('Invalid argument: {}'.format(exact_match))

        if not isinstance(ignore_case, bool):
            raise TypeError('Invalid argument: {}'.format(ignore_case))

        process32 = process.process_from_name(
            process_name,
            exact_match,
            ignore_case,
        )

        if not process32:
            raise exception.ProcessNotFound(process_name)
        self.process_id = process32.th32ProcessID
        self.open_process_from_id(self.process_id)

    def open_process_from_id(self, process_id):
        if not process_id or not isinstance(process_id, int):
            raise TypeError('Invalid argument: {}'.format(process_id))
        self.process_id = process_id
        self.process_handle = process.open(self.process_id)
        if not self.process_handle:
            raise exception.CouldNotOpenProcess(self.process_id)
        logger.debug('Process {} is being debugged'.format(
            process_id
        ))

    def close_process(self):
        if not self.process_handle:
            raise exception.ProcessError('You must open a process before calling this method')
        process.close_handle(self.process_handle)
        self.process_handle = None
        self.process_id = None
        self.is_WoW64 = None
        self.py_run_simple_string = None
        self._python_injected = None
        if self.thread_handle:
            process.close_handle(self.thread_handle)

    def allocate(self, size):
        if not size or not isinstance(size, int):
            raise TypeError('Invalid argument: {}'.format(size))
        if not self.process_handle:
            raise exception.ProcessError('You must open a process before calling this method')
        address = memory.allocate_memory(self.process_handle, size)
        return address

    def free(self, address):
        if not address or not isinstance(address, int):
            raise TypeError('Invalid argument: {}'.format(address))
        if not self.process_handle:
            raise exception.ProcessError('You must open a process before calling this method')
        return memory.free_memory(self.process_handle, address)

    def pattern_scan_all(self, pattern, *, return_multiple=False):
        return pattern.pattern_scan_all(self.process_handle, pattern, return_multiple=return_multiple)

    def pattern_scan_module(self, pattern, module, *, return_multiple=False):
        if isinstance(module, str):
            module = process.module_from_name(self.process_handle, module)

        return pattern.pattern_scan_module(
            self.process_handle,
            module,
            pattern,
            return_multiple=return_multiple
        )

    @property
    def process_base(self):
        if not self.process_id:
            raise TypeError('You must open a process before calling this property')
        base_module = process.base_module(self.process_handle)
        if not base_module:
            raise exception.ProcessError("Could not find process first module")
        return base_module

    @property
    def base_address(self):
        return self.process_base.lpBaseOfDll

    @property
    @functools.lru_cache(maxsize=1)
    def main_thread(self):
        if not self.process_id:
            raise exception.ProcessError('You must open a process before calling this method')
        threads = process.enum_process_thread(self.process_id)
        threads = sorted(threads, key=lambda k: k.creation_time)

        if not threads:
            raise exception.ProcessError('Could not list process thread')

        main_thread = threads[0]
        main_thread = thread.Thread(self.process_handle, main_thread)
        return main_thread

    @property
    @functools.lru_cache(maxsize=1)
    def main_thread_id(self):
        if not self.process_id:
            raise exception.ProcessError('You must open a process before calling this method')
        return self.main_thread.thread_id

    def read_bytes(self, address, length):
        if not self.process_handle:
            raise exception.ProcessError('You must open a process before calling this method')
        try:
            value = memory.read_bytes(self.process_handle, address, length)
        except exception.WinAPIError as e:
            raise exception.MemoryReadError(address, length, e.error_code)
        return value

    def read_ctype(self, address, ctype, *, get_py_value=True, raw_bytes=False):
        if not self.process_handle:
            raise exception.ProcessError('You must open a process before calling this method')
        try:
            value = memory.read_ctype(self.process_handle, address, ctype, get_py_value=get_py_value, raw_bytes=raw_bytes)
        except exception.WinAPIError as e:
            raise exception.MemoryReadError(address, ctypes.sizeof(ctype), e.error_code)
        return value

    def read_bool(self, address):
        if not self.process_handle:
            raise exception.ProcessError('You must open a process before calling this method')
        try:
            value = memory.read_bool(self.process_handle, address)
        except exception.WinAPIError as e:
            raise exception.MemoryReadError(address, struct.calcsize('?'), e.error_code)
        return value

    def read_char(self, address):
        if not self.process_handle:
            raise exception.ProcessError('You must open a process before calling this method')
        try:
            value = memory.read_char(self.process_handle, address)
        except exception.WinAPIError as e:
            raise exception.MemoryReadError(address, struct.calcsize('b'), e.error_code)
        return value

    def read_uchar(self, address):
        if not self.process_handle:
            raise exception.ProcessError('You must open a process before calling this method')
        try:
            value = memory.read_uchar(self.process_handle, address)
        except exception.WinAPIError as e:
            raise exception.MemoryReadError(address, struct.calcsize('B'), e.error_code)
        return value

    def read_int(self, address):
        if not self.process_handle:
            raise exception.ProcessError('You must open a process before calling this method')
        try:
            value = memory.read_int(self.process_handle, address)
        except exception.WinAPIError as e:
            raise exception.MemoryReadError(address, struct.calcsize('i'), e.error_code)
        return value

    def read_uint(self, address):
        if not self.process_handle:
            raise exception.ProcessError('You must open a process before calling this method')
        try:
            value = memory.read_uint(self.process_handle, address)
        except exception.WinAPIError as e:
            raise exception.MemoryReadError(address, struct.calcsize('I'), e.error_code)
        return value

    def read_short(self, address):
        if not self.process_handle:
            raise exception.ProcessError('You must open a process before calling this method')
        try:
            value = memory.read_short(self.process_handle, address)
        except exception.WinAPIError as e:
            raise exception.MemoryReadError(address, struct.calcsize('h'), e.error_code)
        return value

    def read_ushort(self, address):
        if not self.process_handle:
            raise exception.ProcessError('You must open a process before calling this method')
        try:
            value = memory.read_ushort(self.process_handle, address)
        except exception.WinAPIError as e:
            raise exception.MemoryReadError(address, struct.calcsize('H'), e.error_code)
        return value

    def read_float(self, address):
        if not self.process_handle:
            raise exception.ProcessError('You must open a process before calling this method')
        try:
            value = memory.read_float(self.process_handle, address)
        except exception.WinAPIError as e:
            raise exception.MemoryReadError(address, struct.calcsize('f'), e.error_code)
        return value

    def read_long(self, address):
        if not self.process_handle:
            raise exception.ProcessError('You must open a process before calling this method')
        try:
            value = memory.read_long(self.process_handle, address)
        except exception.WinAPIError as e:
            raise exception.MemoryReadError(address, struct.calcsize('l'), e.error_code)
        return value

    def read_ulong(self, address):
        if not self.process_handle:
            raise exception.ProcessError('You must open a process before calling this method')
        try:
            value = memory.read_ulong(self.process_handle, address)
        except exception.WinAPIError as e:
            raise exception.MemoryReadError(address, struct.calcsize('L'), e.error_code)
        return value

    def read_longlong(self, address):
        if not self.process_handle:
            raise exception.ProcessError('You must open a process before calling this method')
        try:
            value = memory.read_longlong(self.process_handle, address)
        except exception.WinAPIError as e:
            raise exception.MemoryReadError(address, struct.calcsize('q'), e.error_code)
        return value

    def read_ulonglong(self, address):
        if not self.process_handle:
            raise exception.ProcessError('You must open a process before calling this method')
        try:
            value = memory.read_ulonglong(self.process_handle, address)
        except exception.WinAPIError as e:
            raise exception.MemoryReadError(address, struct.calcsize('Q'), e.error_code)
        return value

    def read_double(self, address):
        if not self.process_handle:
            raise exception.ProcessError('You must open a process before calling this method')
        try:
            value = memory.read_double(self.process_handle, address)
        except exception.WinAPIError as e:
            raise exception.MemoryReadError(address, struct.calcsize('d'), e.error_code)
        return value

    def read_string(self, address, byte=50):
        if not self.process_handle:
            raise exception.ProcessError('You must open a process before calling this method')
        if not byte or not isinstance(byte, int):
            raise TypeError('Invalid argument: {}'.format(byte))
        try:
            value = memory.read_string(self.process_handle, address, byte)
        except exception.WinAPIError as e:
            raise exception.MemoryReadError(address, byte, e.error_code)
        return value

    # TODO: make length optional, remove in 2.0
    def write_bytes(self, address, value, length):
        if not self.process_handle:
            raise exception.ProcessError('You must open a process before calling this method')
        if value is None or not isinstance(value, bytes):
            raise TypeError('Invalid argument: {}'.format(value))
        try:
            memory.write_bytes(self.process_handle, address, value, length)
        except exception.WinAPIError as e:
            raise exception.MemoryWriteError(address, value, e.error_code)

    def write_ctype(self, address, ctype):
        if not self.process_handle:
            raise exception.ProcessError('You must open a process before calling this method')
        try:
            memory.write_ctype(self.process_handle, address, ctype)
        except exception.WinAPIError as e:
            raise exception.MemoryWriteError(address, ctype, e.error_code)

    def write_bool(self, address, value):
        if not self.process_handle:
            raise exception.ProcessError('You must open a process before calling this method')
        if value is None or not isinstance(value, bool):
            raise TypeError('Invalid argument: {}'.format(value))
        try:
            memory.write_bool(self.process_handle, address, value)
        except exception.WinAPIError as e:
            raise exception.MemoryWriteError(address, value, e.error_code)

    def write_int(self, address, value):
        if not self.process_handle:
            raise exception.ProcessError('You must open a process before calling this method')
        if value is None or not isinstance(value, int):
            raise TypeError('Invalid argument: {}'.format(value))
        try:
            memory.write_int(self.process_handle, address, value)
        except exception.WinAPIError as e:
            raise exception.MemoryWriteError(address, value, e.error_code)

    def write_uint(self, address, value):
        if not self.process_handle:
            raise exception.ProcessError('You must open a process before calling this method')
        if value is None or not isinstance(value, int):
            raise TypeError('Invalid argument: {}'.format(value))
        try:
            memory.write_uint(self.process_handle, address, value)
        except exception.WinAPIError as e:
            raise exception.MemoryWriteError(address, value, e.error_code)

    def write_short(self, address, value):
        if not self.process_handle:
            raise exception.ProcessError('You must open a process before calling this method')
        if value is None or not isinstance(value, int):
            raise TypeError('Invalid argument: {}'.format(value))
        try:
            memory.write_short(self.process_handle, address, value)
        except exception.WinAPIError as e:
            raise exception.MemoryWriteError(address, value, e.error_code)

    def write_ushort(self, address, value):
        if not self.process_handle:
            raise exception.ProcessError('You must open a process before calling this method')
        if value is None or not isinstance(value, int):
            raise TypeError('Invalid argument: {}'.format(value))
        try:
            memory.write_ushort(self.process_handle, address, value)
        except exception.WinAPIError as e:
            raise exception.MemoryWriteError(address, value, e.error_code)

    def write_float(self, address, value):
        if not self.process_handle:
            raise exception.ProcessError('You must open a process before calling this method')
        if value is None or not isinstance(value, float):
            raise TypeError('Invalid argument: {}'.format(value))
        try:
            memory.write_float(self.process_handle, address, value)
        except exception.WinAPIError as e:
            raise exception.MemoryWriteError(address, value, e.error_code)

    def write_long(self, address, value):
        if not self.process_handle:
            raise exception.ProcessError('You must open a process before calling this method')
        if value is None or not isinstance(value, int):
            raise TypeError('Invalid argument: {}'.format(value))
        try:
            memory.write_long(self.process_handle, address, value)
        except exception.WinAPIError as e:
            raise exception.MemoryWriteError(address, value, e.error_code)

    def write_ulong(self, address, value):
        if not self.process_handle:
            raise exception.ProcessError('You must open a process before calling this method')
        if value is None or not isinstance(value, int):
            raise TypeError('Invalid argument: {}'.format(value))
        try:
            memory.write_ulong(self.process_handle, address, value)
        except exception.WinAPIError as e:
            raise exception.MemoryWriteError(address, value, e.error_code)

    def write_longlong(self, address, value):
        if not self.process_handle:
            raise exception.ProcessError('You must open a process before calling this method')
        if value is None or not isinstance(value, int):
            raise TypeError('Invalid argument: {}'.format(value))
        try:
            memory.write_longlong(self.process_handle, address, value)
        except exception.WinAPIError as e:
            raise exception.MemoryWriteError(address, value, e.error_code)

    def write_ulonglong(self, address, value):
        if not self.process_handle:
            raise exception.ProcessError('You must open a process before calling this method')
        if value is None or not isinstance(value, int):
            raise TypeError('Invalid argument: {}'.format(value))
        try:
            memory.write_ulonglong(self.process_handle, address, value)
        except exception.WinAPIError as e:
            raise exception.MemoryWriteError(address, value, e.error_code)

    def write_double(self, address, value):
        if not self.process_handle:
            raise exception.ProcessError('You must open a process before calling this method')
        if value is None or not isinstance(value, float):
            raise TypeError('Invalid argument: {}'.format(value))
        try:
            memory.write_double(self.process_handle, address, value)
        except exception.WinAPIError as e:
            raise exception.MemoryWriteError(address, value, e.error_code)

    def write_string(self, address, value):
        if not self.process_handle:
            raise exception.ProcessError('You must open a process before calling this method')
        if value is None or not isinstance(value, str):
            raise TypeError('Invalid argument: {}'.format(value))
        value = value.encode()
        try:
            memory.write_string(self.process_handle, address, value)
        except exception.WinAPIError as e:
            raise exception.MemoryWriteError(address, value, e.error_code)

    def write_char(self, address, value):
        if not self.process_handle:
            raise exception.ProcessError('You must open a process before calling this method')
        if value is None or not isinstance(value, str):
            raise TypeError('Invalid argument: {}'.format(value))
        value = value.encode()
        try:
            memory.write_char(self.process_handle, address, value)
        except exception.WinAPIError as e:
            raise exception.MemoryWriteError(address, value, e.error_code)

    def write_uchar(self, address, value):
        if not self.process_handle:
            raise exception.ProcessError('You must open a process before calling this method')
        if value is None or not isinstance(value, int):
            raise TypeError('Invalid argument: {}'.format(value))
        try:
            memory.write_uchar(self.process_handle, address, value)
        except exception.WinAPIError as e:
            raise exception.MemoryWriteError(address, value, e.error_code)
