import struct
from unicorn import UC_PROT_ALL, Uc, UC_HOOK_CODE
import defines

DYNAMIC_HOOKS = {}

def align_up(value: int, alignment: int) -> int:
    return (value + alignment - 1) & ~(alignment - 1)

def allocate_mock(size: int, alignment: int = 0x10) -> int:
    """Dynamically allocate memory for mocked protocols/stubs."""
    addr = align_up(defines._mock_ptr, alignment)
    if addr + size > defines.MOCK_BASE + defines.MOCK_SIZE:
        raise MemoryError(f"Mock memory exhausted: cannot allocate 0x{size:X} bytes")
    defines._mock_ptr = addr + size
    return addr

def allocate_mock_bytes(mu: Uc, data: bytes) -> int:
    addr = allocate_mock(len(data))
    mu.mem_write(addr, data)
    return addr

def map_mock_base(mu):
    mu.mem_map(defines.MOCK_BASE, defines.MOCK_SIZE, UC_PROT_ALL)

def ensure_mapped(mu: Uc, addr: int, length: int):
    """Ensure all pages covering [addr, addr+length) are mapped.

    This avoids UcError on mem_write when the destination isn't mapped.
    """
    if length <= 0:
        return
    start = addr & ~(defines.PAGE_SIZE - 1)
    end = align_up(addr + length, defines.PAGE_SIZE)
    cur = start
    while cur < end:
        try:
            mu.mem_map(cur, defines.PAGE_SIZE, UC_PROT_ALL)
        except Exception:
            # If already mapped or mapping fails, ignore and continue
            pass
        cur += defines.PAGE_SIZE

def register_dynamic_hook(addr: int, protocol: any, func_idx: int):
    DYNAMIC_HOOKS[addr] = (protocol, func_idx)

def call_dynamic_hook(mu: Uc, addr: int):
    if addr not in DYNAMIC_HOOKS:
        print(f"[UEFI] Dynamic hook at 0x{addr:X} not found")
        mu.emu_stop()
        return
    protocol, func_idx = DYNAMIC_HOOKS[addr]
    protocol.handle_hook(mu, func_idx)

def read_string(mu: Uc, addr: int) -> str:
    """Read a null-terminated string from emulated memory."""
    data = bytearray()
    while True:
        b = mu.mem_read(addr, 1)[0]
        if b == 0:
            break
        data.append(b)
        addr += 1
    return data.decode("utf-8", errors="ignore")

def hexdump(data: bytes):
    for i in range(0, len(data), 16):
        ascii_str = [chr(b) if 32 <= b <= 126 else '.' for b in data[i:i+16]]
        print(f"{i:04X}: {data[i:i+16].hex()} | {''.join(ascii_str)}")

def guid_to_str(guid: bytes) -> str:
    # little endian
    return f"{guid[0:4][::-1].hex().upper()}-{guid[4:6][::-1].hex().upper()}-{guid[6:8][::-1].hex().upper()}-{guid[8:10].hex().upper()}-{guid[10:16].hex().upper()}"

def set_simple_hook(mu: Uc, addr: int, hook: callable):
    mu.hook_add(UC_HOOK_CODE, hook, begin=addr, end=addr)