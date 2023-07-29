import os
os.chdir(os.environ['USERPROFILE']+"\\"+"Area")
import ctypes
import struct

import memory
import exception


class RemotePointer(object):


    ALIGNMENTS = {
        'little-endian': '<',
        'big-endian': '>'
    }

    def __init__(self, handle, v, endianess='little-endian'):
        self._set_value(v)

        if endianess not in RemotePointer.ALIGNMENTS:
            # TODO: maybe make this a ValueError in next major version
            raise exception.memAlignmentError(
                "{endianess} is not a valid alignment, it should be one from: {alignments}".format(**{
                    'endianess': endianess,
                    'alignments': ', '.join(RemotePointer.ALIGNMENTS.keys())
                })
            )
        self.endianess = endianess

        self.handle = handle
        self._memory_value = None

    def __bool__(self):
        return bool(self.value)

    def _set_value(self, v):

        if isinstance(v, RemotePointer):
            self.v = v.cvalue
        elif isinstance(v, int) and not hasattr(v, 'value'):
            if v > 2147483647:
                self.v = ctypes.c_ulonglong(v)
            else:
                self.v = ctypes.c_uint(v)
        elif isinstance(v, ctypes._SimpleCData):
            self.v = v
        else:
            raise exception.memTypeError(
                "{type} is not an allowed type, it should be one from: {allowed_types}".format(**{
                    'type': 'None' if not v else str(type(v)),
                    'allowed_types': ', '.join([
                        'RemotePointer', 'ctypes', 'int'
                    ])
                }))

    def __add__(self, a):
        self._memory_value = self.value + a
        return self.cvalue

    @property
    def value(self):

        if self._memory_value:
            return self._memory_value
        content = memory.read_bytes(
            self.handle, self.v.value, struct.calcsize(self.v._type_)
        )
        fmt = '{alignment}{type}'.format(**{
            'alignment': RemotePointer.ALIGNMENTS[self.endianess],
            'type': self.v._type_
        })
        content = struct.unpack(fmt, content)
        self._memory_value = content[0]
        return self._memory_value

    @property
    def cvalue(self):

        v = self.v.__class__(self.value)
        return v
