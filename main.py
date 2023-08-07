#
import os
os.chdir(os.environ['USERPROFILE']+"\\"+"Area")
import ressources.Addresses
import pattern

def main():
    mem = ressources.Addresses.GameClass("saplogon.exe")
    bytes_pattern = b".\x50\.\.\.\.\x00\x57\x00\.\.\.\.\.\x00\x3A\x00\x20\x00\x30\x00" \
            b"\x37\x00\x20\x00\x2D\x00\x20\x00\x32\x00\x37\x00"
    addr = pattern.pattern_scan_all(mem.handle,bytes_pattern)
    mem.readBytes(addr,20)
 
if __name__ == '__main__':
    pass
