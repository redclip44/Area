import os
os.chdir(os.environ['USERPROFILE']+"\\"+"Area")
import sys

import memory
import ressources.kernel32
import ressources.structure

try:
    # faster than builtin re
    import regex as re
except ImportError:
    import re


# TODO: warn that pattern is a regex and may need to be escaped
# TODO: 2.0 rename to pattern_scan_page
def scan_pattern_page(handle, address, pattern, *, return_multiple=False):

    mbi = memory.virtual_query(handle, address)
    next_region = mbi.BaseAddress + mbi.RegionSize
    allowed_protections = [
        ressources.structure.MEMORY_PROTECTION.PAGE_EXECUTE,
        ressources.structure.MEMORY_PROTECTION.PAGE_EXECUTE_READ,
        ressources.structure.MEMORY_PROTECTION.PAGE_EXECUTE_READWRITE,
        ressources.structure.MEMORY_PROTECTION.PAGE_READWRITE,
        ressources.structure.MEMORY_PROTECTION.PAGE_READONLY,
    ]
    if mbi.state != ressources.structure.MEMORY_STATE.MEM_COMMIT or mbi.protect not in allowed_protections:
        return next_region, None

    page_bytes = memory.read_bytes(handle, address, mbi.RegionSize)

    if not return_multiple:
        found = None
        match = re.search(pattern, page_bytes, re.DOTALL)

        if match:
            found = address + match.span()[0]

    else:
        found = []

        for match in re.finditer(pattern, page_bytes, re.DOTALL):
            found_address = address + match.span()[0]
            found.append(found_address)

    return next_region, found


def pattern_scan_module(handle, module, pattern, *, return_multiple=False):

    base_address = module.lpBaseOfDll
    max_address = module.lpBaseOfDll + module.SizeOfImage
    page_address = base_address

    if not return_multiple:
        found = None
        while page_address < max_address:
            page_address, found = scan_pattern_page(handle, page_address, pattern)

            if found:
                break

    else:
        found = []
        while page_address < max_address:
            page_address, new_found = scan_pattern_page(handle, page_address, pattern, return_multiple=True)

            if new_found:
                found += new_found

    return found


def pattern_scan_all(handle, pattern, *, return_multiple=False):

    next_region = 0

    found = []
    user_space_limit = 0x7FFFFFFF0000 if sys.maxsize > 2**32 else 0x7fff0000
    while next_region < user_space_limit:
        next_region, page_found = scan_pattern_page(
            handle,
            next_region,
            pattern,
            return_multiple=return_multiple
        )

        if not return_multiple and page_found:
            return page_found

        if page_found:
            found += page_found

    if not return_multiple:
        return None

    return found
