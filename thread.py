import os
os.chdir(os.environ['USERPROFILE']+"\\"+"Area")
import ctypes

import memory
import ressources.kernel32
import ressources.ntdll
import ressources.structure


class Thread(object):


    def __init__(self, process_handle, th_entry_32):
        self.process_handle = process_handle
        self.thread_id = th_entry_32.th32ThreadID
        self.th_entry_32 = th_entry_32
        self.teb_address = None
        # teb should be tested, not working on x64
        # self.teb = self._query_teb()

    def _query_teb(self):

        THREAD_QUERY_INFORMATION = 0x0040

        thread_handle = ressources.kernel32.OpenThread(
            THREAD_QUERY_INFORMATION, False, self.th_entry_32.th32ThreadID
        )
        res = ressources.structure.THREAD_BASIC_INFORMATION()
        ThreadBasicInformation = 0x0

        ressources.ntdll.NtQueryInformationThread(
            thread_handle,
            ThreadBasicInformation,
            ctypes.byref(res),
            ctypes.sizeof(res),
            None
        )
        self.teb_address = res.TebBaseAddress
        data = memory.read_bytes(
            self.process_handle,
            res.TebBaseAddress,
            ctypes.sizeof(ressources.structure.SMALL_TEB)
        )
        teb = ressources.structure.SMALL_TEB.from_buffer_copy(data)
        ressources.kernel32.CloseHandle(thread_handle)
        return teb
