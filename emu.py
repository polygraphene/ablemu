#!/usr/bin/env -S uv run --script
"""
Qualcomm ABL (abl.pe) ARM64 Emulator using Unicorn Engine.

Parses the PE file, maps all sections into emulated memory,
sets up a minimal UEFI environment (stack, heap, EFI_SYSTEM_TABLE stub),
and begins emulation at the PE entry point.
"""

import struct
import sys
import os
import lzma
import argparse
import binascii

from unicorn import *
from unicorn.arm64_const import *

import pefile
os.path.join(os.path.dirname(__file__))
from protocols import (BlockIoProtocol,
  DevicePathProtocol,
  PartitionEntryProtocol,
  VerifiedBootProtocol,
  KernelInterfaceProtocol,
  MemCardInfoProtocol,
  RamPartitionProtocol,
  UsbDeviceProtocol,
  StatusCodeProtocol,
  GraphicsOutputProtocol,
  SimpleTextInputProtocol,
  SimpleTextOutputProtocol,
  HiiFontProtocol,
  Hash2Protocol,
  QSEEComProtocol,
  QcomScmProtocol,
  ChipInfoProtocol,
  PlatformInfoProtocol,
  ResetReasonProtocol,
  feed_fastboot_cmd,
  set_reset_reason)
from utils import align_up, allocate_mock, map_mock_base, ensure_mapped, call_dynamic_hook, guid_to_str, set_simple_hook
from format_string import process_format_string
from partitions import PartitionList
import defines

STRNCMP_ADDR = 0x1ddc

partition_list = PartitionList()
blockio_protocol = BlockIoProtocol(partition_list)
device_path_protocol = DevicePathProtocol(partition_list)
partition_entry_protocol = PartitionEntryProtocol(partition_list)
verified_boot_protocol = VerifiedBootProtocol()
kernel_interface_protocol = KernelInterfaceProtocol()
mem_card_info_protocol = MemCardInfoProtocol()
ram_partition_protocol = RamPartitionProtocol()
usb_device_protocol = UsbDeviceProtocol()
status_code_protocol = StatusCodeProtocol()
graphics_output_protocol = GraphicsOutputProtocol()
simple_text_input_protocol = SimpleTextInputProtocol()
simple_text_output_protocol = SimpleTextOutputProtocol()
hii_font_protocol = HiiFontProtocol()
hash2_protocol = Hash2Protocol()
qsee_com_protocol = QSEEComProtocol()
qcom_scm_protocol = QcomScmProtocol()
chip_info_protocol = ChipInfoProtocol()
platform_info_protocol = PlatformInfoProtocol()
reset_reason_protocol = ResetReasonProtocol()

# Registry for protocol lookups
PROTOCOL_REGISTRY = {
    defines.EFI_BLOCK_IO_PROTOCOL_GUID: blockio_protocol,
    defines.EFI_DEVICE_PATH_PROTOCOL_GUID: device_path_protocol,
    defines.EFI_PARTITION_ENTRY_PROTOCOL_GUID: partition_entry_protocol,
    defines.EFI_VERIFIED_BOOT_PROTOCOL_GUID: verified_boot_protocol,
    defines.QCOM_KERNEL_INTERFACE_PROTOCOL_GUID: kernel_interface_protocol,
    defines.EFI_MEM_CARD_INFO_PROTOCOL_GUID: mem_card_info_protocol,
    defines.EFI_RAM_PARTITION_PROTOCOL_GUID: ram_partition_protocol,
    defines.EFI_USB_DEVICE_PROTOCOL_GUID: usb_device_protocol,
    defines.EFI_STATUS_CODE_PROTOCOL_GUID: status_code_protocol,
    defines.EFI_GRAPHICS_OUTPUT_PROTOCOL_GUID: graphics_output_protocol,
    defines.EFI_SIMPLE_TEXT_INPUT_PROTOCOL_GUID: simple_text_input_protocol,
    defines.EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL_GUID: simple_text_output_protocol,
    defines.EFI_HII_FONT_PROTOCOL_GUID: hii_font_protocol,
    defines.EFI_HASH2_PROTOCOL_GUID: hash2_protocol,
    defines.EFI_QSEECOM_PROTOCOL_GUID: qsee_com_protocol,
    defines.QCOM_SCM_PROTOCOL_GUID: qcom_scm_protocol,
    defines.EFI_CHIPINFO_PROTOCOL_GUID: chip_info_protocol,
    defines.EFI_PLATFORMINFO_PROTOCOL_GUID: platform_info_protocol,
    defines.EFI_RESETREASON_PROTOCOL_GUID: reset_reason_protocol,
}

def heap_alloc(size, alignment=16):
    global _malloc_ptr, _malloc_map
    allocated_addr = align_up(_malloc_ptr, alignment)
    _malloc_ptr = allocated_addr + align_up(size, alignment)
    if _malloc_ptr > defines.HEAP_BASE + defines.HEAP_SIZE:
        return 0
    _malloc_map[allocated_addr] = size
    return allocated_addr

# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

# Maximum instructions to execute before we bail out (safety net).
MAX_INSN = 20_000_000_000

# Globals to track loaded PE bounds for stack scanning
IMAGE_BASE = 0
IMAGE_SIZE = 0

# Simple heap allocator for EFI_AllocatePool / EFI_AllocatePages
_malloc_ptr = defines.HEAP_BASE  # Start of available heap
_malloc_map = {}  # Track allocated blocks for FreePool



# Debugging: breakpoints and single-step execution
breakpoints = set()  # Set of breakpoint addresses
step_mode = False  # Single-step execution flag
emulation_paused = False  # Flag to pause emulation at breakpoint

# ---------------------------------------------------------------------------
# PE Loader
# ---------------------------------------------------------------------------

def load_pe(mu: Uc, data: bytes) -> tuple[int, int]:
    """Load a PE file into the Unicorn address space.

    Maps each section with appropriate permissions and returns the
    absolute entry-point VA and image_base.
    """
    global IMAGE_BASE, IMAGE_SIZE
    pe = pefile.PE(data=data, fast_load=False)
    image_base = pe.OPTIONAL_HEADER.ImageBase

    # Calculate the total image size (rounded up to page boundary)
    image_size = align_up(pe.OPTIONAL_HEADER.SizeOfImage, defines.PAGE_SIZE)
    
    IMAGE_BASE = image_base
    IMAGE_SIZE = image_size

    print(f"[PE] ImageBase        = 0x{image_base:016X}")
    print(f"[PE] SizeOfImage      = 0x{image_size:X}")
    print(f"[PE] AddressOfEntryPt = 0x{pe.OPTIONAL_HEADER.AddressOfEntryPoint:X}")
    print(f"[PE] Number of sections: {len(pe.sections)}")

    # Map the full image region first (RWX for simplicity; sections will
    # overwrite the relevant portions).
    mu.mem_map(image_base, image_size, UC_PROT_ALL)

    # Write PE headers
    header_size = pe.OPTIONAL_HEADER.SizeOfHeaders
    mu.mem_write(image_base, pe.get_data()[:header_size])

    # Map each section
    for sec in pe.sections:
        name = sec.Name.rstrip(b"\x00").decode("ascii", errors="replace")
        va   = image_base + sec.VirtualAddress
        raw  = sec.get_data()
        vsize = align_up(sec.Misc_VirtualSize, defines.PAGE_SIZE)

        print(f"  [{name:8s}]  VA=0x{va:016X}  VSize=0x{vsize:X}  "
              f"RawSize=0x{len(raw):X}")

        mu.mem_write(va, raw)

    entry_point = image_base + pe.OPTIONAL_HEADER.AddressOfEntryPoint
    print(f"[PE] Entry point (abs) = 0x{entry_point:016X}")
    return entry_point, image_base


# ---------------------------------------------------------------------------
# UEFI stub helpers
# ---------------------------------------------------------------------------

def setup_uefi_tables(mu: Uc, chip_id: int, chip_version: int):
    """Create minimal EFI_SYSTEM_TABLE / EFI_BOOT_SERVICES stubs.

    The actual function pointers inside the table point to the RETURN_ADDR
    so that any UEFI call will immediately trigger our hook and we can
    handle or skip it.
    """
    global EFI_IMAGE_HANDLE, UEFI_STUB_REGION, MOCK_REGION, MOCK_FUNC_ADDR
    global MOCK_HANDLE_ARRAY_ADDR

    # Map the entire MOCK region
    map_mock_base(mu)

    # Allocate addresses
    EFI_IMAGE_HANDLE      = allocate_mock(0) # Logic only
    UEFI_STUB_REGION      = allocate_mock(defines.UEFI_STUB_SIZE)
    MOCK_REGION           = allocate_mock(defines.MOCK_REGION_SIZE)
    MOCK_FUNC_ADDR        = allocate_mock(16)

    
    MOCK_HANDLE_ARRAY_ADDR     = allocate_mock(0x100)

    mu.mem_map(defines.EFI_SYSTEM_TABLE_ADDR, defines.EFI_TABLE_REGION_SIZE, UC_PROT_ALL)

    # Lay out a very rough EFI_SYSTEM_TABLE at EFI_SYSTEM_TABLE_ADDR.
    # The first 8 bytes are the Hdr.Signature (u64), then Hdr.Revision, etc.
    # We only care about the BootServices pointer at offset 0x60.
    boot_services_addr = defines.EFI_SYSTEM_TABLE_ADDR + 0x1000
    runtime_services_addr = defines.EFI_SYSTEM_TABLE_ADDR + 0x2000
    dxe_services_addr = defines.EFI_SYSTEM_TABLE_ADDR + 0x3000
    config_table_addr = defines.EFI_SYSTEM_TABLE_ADDR + 0x4000

    # Zero-fill the region first
    mu.mem_write(defines.EFI_SYSTEM_TABLE_ADDR, b"\x00" * defines.EFI_TABLE_REGION_SIZE)

    # EFI_SYSTEM_TABLE.Signature = "IBI SYST" (u64)
    mu.mem_write(defines.EFI_SYSTEM_TABLE_ADDR, struct.pack("<Q", 0x5453595320494249))
    # EFI_SYSTEM_TABLE.BootServices (offset 0x60)
    mu.mem_write(defines.EFI_SYSTEM_TABLE_ADDR + 0x60,
                 struct.pack("<Q", boot_services_addr))
    # EFI_SYSTEM_TABLE.NumberOfTableEntries (offset 0x68)
    mu.mem_write(defines.EFI_SYSTEM_TABLE_ADDR + 0x68,
                 struct.pack("<Q", 2))  # Now we have 2 tables: DxeServices and HobList
    # EFI_SYSTEM_TABLE.ConfigurationTable (offset 0x70)
    mu.mem_write(defines.EFI_SYSTEM_TABLE_ADDR + 0x70,
                 struct.pack("<Q", config_table_addr))
    mu.mem_write(defines.EFI_SYSTEM_TABLE_ADDR + 0x58,
                 struct.pack("<Q", runtime_services_addr))

    # Initialize protocols first so we have their addresses
    graphics_output_protocol.setup(mu)
    simple_text_input_protocol.setup(mu)
    simple_text_output_protocol.setup(mu)
    hii_font_protocol.setup(mu, allocator=heap_alloc)
    status_code_protocol.setup(mu, MOCK_REGION)

    # Add console handles and protocols to System Table
    console_in_handle = 0xDE000010
    console_out_handle = 0xDE000020
    
    # ConsoleInHandle (0x28), ConIn (0x30)
    mu.mem_write(defines.EFI_SYSTEM_TABLE_ADDR + 0x28, struct.pack("<Q", console_in_handle))
    mu.mem_write(defines.EFI_SYSTEM_TABLE_ADDR + 0x30, struct.pack("<Q", simple_text_input_protocol.addr))
    
    # ConsoleOutHandle (0x38), ConOut (0x40)
    mu.mem_write(defines.EFI_SYSTEM_TABLE_ADDR + 0x38, struct.pack("<Q", console_out_handle))
    mu.mem_write(defines.EFI_SYSTEM_TABLE_ADDR + 0x40, struct.pack("<Q", simple_text_output_protocol.addr))
    
    # StandardErrorHandle (0x48), StdErr (0x50)
    mu.mem_write(defines.EFI_SYSTEM_TABLE_ADDR + 0x48, struct.pack("<Q", console_out_handle))
    mu.mem_write(defines.EFI_SYSTEM_TABLE_ADDR + 0x50, struct.pack("<Q", simple_text_output_protocol.addr))

    stub_offset = 0

    def create_stub(service_type, table_offset):
        nonlocal stub_offset
        addr = UEFI_STUB_REGION + stub_offset
        
        # We write a small ARM64 stub:
        # MOV X16, #table_offset
        # MOV X17, #service_type (0=Boot, 1=Runtime)
        # BRK #1
        # RET
        
        # MOVZ X16, #table_offset, LSL 0  -> 0xD2800000 | (table_offset << 5) | 16
        insn1 = (0xD2800000 | (table_offset << 5) | 16)
        # MOVZ X17, #service_type, LSL 0  -> 0xD2800000 | (service_type << 5) | 17
        insn2 = (0xD2800000 | (service_type << 5) | 17)
        # BRK #1                          -> 0xD4200020
        insn3 = 0xD4200020
        # RET                             -> 0xD65F03C0
        insn4 = 0xD65F03C0
        
        mu.mem_write(addr, struct.pack("<IIII", insn1, insn2, insn3, insn4))
        stub_offset += 16
        return addr

    # Fill BootServices table entries with individual stubs
    for off in range(0, 0x200, 8):
        stub_addr = create_stub(0, off)
        mu.mem_write(boot_services_addr + off,
                     struct.pack("<Q", stub_addr))

    # Same for RuntimeServices
    for off in range(0, 0x200, 8):
        stub_addr = create_stub(1, off)
        mu.mem_write(runtime_services_addr + off,
                     struct.pack("<Q", stub_addr))

    # Create generic mock function for DXE Services table
    mu.mem_write(MOCK_FUNC_ADDR, struct.pack("<II", 0xD4200040, 0xD65F03C0))
    for off in range(0, 0x200, 8):
        mu.mem_write(dxe_services_addr + off, struct.pack("<Q", MOCK_FUNC_ADDR))

    # Write Configuration Table Entry 0: DxeServicesTable
    # EFI_GUID gEfiDxeServicesTableGuid = {0x05AD34BA, 0x6F02, 0x4214, {0x95, 0x2E, 0x4D, 0xA0, 0x39, 0x8E, 0x2B, 0xB9}}
    dxe_guid = struct.pack("<IHH8B", 0x05AD34BA, 0x6F02, 0x4214, 0x95, 0x2E, 0x4D, 0xA0, 0x39, 0x8E, 0x2B, 0xB9)
    # Configuration Table is an array of EFI_CONFIGURATION_TABLE structs (GUID + void*) = 24 bytes
    mu.mem_write(config_table_addr, dxe_guid)
    mu.mem_write(config_table_addr + 16, struct.pack("<Q", dxe_services_addr))

    # Write Configuration Table Entry 1: HobList
    # EFI_GUID gEfiHobListGuid = {0x7739f24c, 0x93d7, 0x11d4, {0x9a, 0x3a, 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d}}
    hob_guid = struct.pack("<IHH8B", 0x7739F24C, 0x93D7, 0x11D4, 0x9A, 0x3A, 0x00, 0x90, 0x27, 0x3F, 0xC1, 0x4D)
    hob_list_addr = MOCK_REGION + 0x2000
    # Dummy End of HOB List marker: Type = 0xFFFF (EFI_HOB_TYPE_END_OF_HOB_LIST), Length = 8
    mu.mem_write(hob_list_addr, struct.pack("<HH", 0xFFFF, 8))
    
    mu.mem_write(config_table_addr + 24, hob_guid)
    mu.mem_write(config_table_addr + 40, struct.pack("<Q", hob_list_addr))

    # Fill MOCK_REGION with pointers to MOCK_FUNC_ADDR (generic fallback)
    for off in range(0, 0x1000, 8):
        mu.mem_write(MOCK_REGION + off, struct.pack("<Q", MOCK_FUNC_ADDR))

    # Protocol initialization via class methods
    verified_boot_protocol.setup(mu)
    
    blockio_protocol.setup(mu, MOCK_FUNC_ADDR)
    device_path_protocol.setup(mu)
    
    kernel_interface_protocol.setup(mu, MOCK_FUNC_ADDR)
    mem_card_info_protocol.setup(mu)
    ram_partition_protocol.setup(mu)
    usb_device_protocol.setup(mu)
    partition_entry_protocol.setup(mu)
    hash2_protocol.setup(mu)
    qsee_com_protocol.setup(mu)
    qcom_scm_protocol.setup(mu)
    chip_info_protocol.setup(mu, chip_id, chip_version)
    platform_info_protocol.setup(mu)
    reset_reason_protocol.setup(mu)

# Area for BootServices / RuntimeServices function names
EFI_BOOT_SERVICES_NAMES = {
    0x18: "RaiseTPL", 0x20: "RestoreTPL",
    0x28: "AllocatePages", 0x30: "FreePages", 0x38: "GetMemoryMap", 0x40: "AllocatePool", 0x48: "FreePool",
    0x50: "CreateEvent", 0x58: "SetTimer", 0x60: "WaitForEvent", 0x68: "SignalEvent", 0x70: "CloseEvent", 0x78: "CheckEvent",
    0x80: "InstallProtocolInterface", 0x88: "ReinstallProtocolInterface", 0x90: "UninstallProtocolInterface", 0x98: "HandleProtocol", 0xA0: "Reserved",
    0xA8: "RegisterProtocolNotify", 0xB0: "LocateHandle", 0xB8: "LocateDevicePath", 0xC0: "InstallConfigurationTable",
    0xC8: "LoadImage", 0xD0: "StartImage", 0xD8: "Exit", 0xE0: "UnloadImage", 0xE8: "ExitBootServices",
    0xF0: "GetNextMonotonicCount", 0xF8: "Stall", 0x100: "SetWatchdogTimer",
    0x108: "ConnectController", 0x110: "DisconnectController",
    0x118: "OpenProtocol", 0x120: "CloseProtocol", 0x128: "OpenProtocolInformation",
    0x130: "ProtocolsPerHandle", 0x138: "LocateHandleBuffer", 0x140: "LocateProtocol", 0x148: "InstallMultipleProtocolInterfaces", 0x150: "UninstallMultipleProtocolInterfaces",
    0x158: "CalculateCrc32",
    0x160: "CopyMem", 0x168: "SetMem", 0x170: "CreateEventEx"
}

# EFI Runtime Services Table offset mapping
# Reference: EFI_RUNTIME_SERVICES structure in UefiSpec.h
EFI_RUNTIME_SERVICES_NAMES = {
    0x18: "GetTime",
    0x20: "SetTime",
    0x28: "GetWakeupTime",
    0x30: "SetWakeupTime",
    0x38: "SetVirtualAddressMap",
    0x40: "ConvertPointer",
    0x48: "GetVariable",
    0x50: "GetNextVariableName",
    0x58: "SetVariable",
    0x60: "GetNextHighMonotonicCount",
    0x68: "ResetSystem",
    0x70: "UpdateCapsule",
    0x78: "QueryCapsuleCapabilities",
    0x80: "QueryVariableInfo"
}

# ---------------------------------------------------------------------------
# Hook callbacks
# ---------------------------------------------------------------------------

# Track how many instructions we've executed for progress reporting.
_insn_count = 0
_trace_enabled = os.environ.get("EMU_TRACE", "0") == "1"


def hook_code(mu: Uc, address: int, size: int, user_data):
    """Per-instruction hook (only active when EMU_TRACE=1)."""
    global _insn_count
    global step_mode
    global emulation_paused
    global _trace_enabled
    _insn_count += 1

    if _trace_enabled:
        code = mu.mem_read(address, size)
        insn_hex = struct.unpack("<I", code)[0]
        print(f"  >>> 0x{address:016X}: {insn_hex:08X}")
    elif _insn_count % 500_000 == 0:
        print(f"  ... {_insn_count} instructions executed  "
              f"(PC=0x{address:016X})")
    
    # Check for breakpoints
    if address in breakpoints:
        emulation_paused = True
        step_mode = True
        if not _trace_enabled:
            mu.hook_add(UC_HOOK_CODE, hook_code)
        _trace_enabled = True
        print(f"\n[BREAKPOINT] Hit breakpoint at 0x{address:016X}")
        print(f"             PC=0x{address:016X}, LR=0x{mu.reg_read(UC_ARM64_REG_X30):016X}")
        debug_prompt(mu, address)
        return
    
    # Single-step execution mode
    if step_mode:
        print(f"  [STEP] 0x{address:016X}")
        code = mu.mem_read(address, size)
        insn_hex = code.hex()
        print(f"         Instruction: {insn_hex}")
        debug_prompt(mu, address)

    # Hook for AsciiStrnCmp function at 0x255c
    if address == 0x255c:
        x0 = mu.reg_read(UC_ARM64_REG_X0)  # FirstString
        x1 = mu.reg_read(UC_ARM64_REG_X1)  # SecondString
        x2 = mu.reg_read(UC_ARM64_REG_X2)  # Length
        lr = mu.reg_read(UC_ARM64_REG_X30)  # Return address
        
        # Try to read the strings
        first_str = ""
        second_str = ""
        try:
            # Read FirstString (ASCII, null-terminated)
            first_bytes = bytearray()
            for i in range(min(256, x2 if x2 > 0 else 256)):
                byte = mu.mem_read(x0 + i, 1)[0]
                if byte == 0:
                    break
                if 0x20 <= byte <= 0x7E:  # Printable ASCII
                    first_bytes.append(byte)
                else:
                    break
            first_str = first_bytes.decode('ascii', errors='ignore')
        except:
            first_str = "<unreadable>"
        
        try:
            # Read SecondString (ASCII, null-terminated)
            second_bytes = bytearray()
            for i in range(min(256, x2 if x2 > 0 else 256)):
                byte = mu.mem_read(x1 + i, 1)[0]
                if byte == 0:
                    break
                if 0x20 <= byte <= 0x7E:  # Printable ASCII
                    second_bytes.append(byte)
                else:
                    break
            second_str = second_bytes.decode('ascii', errors='ignore')
        except:
            second_str = "<unreadable>"
        
        print(f"[FUNCTION] AsciiStrnCmp called at 0x{address:X}")
        print(f"       -> FirstString (X0=0x{x0:X}): '{first_str}'")
        print(f"       -> SecondString (X1=0x{x1:X}): '{second_str}'")
        print(f"       -> Length (X2): {x2}")
        print(f"       -> Return Address (LR=0x{lr:X})")
    
    # Hook for PartitionGetInfo function at 0x57118
    if address == 0x57118:
        x0 = mu.reg_read(UC_ARM64_REG_X0)  # PartitionName (CHAR16*)
        x1 = mu.reg_read(UC_ARM64_REG_X1)  # BlockIo (OUT)
        x2 = mu.reg_read(UC_ARM64_REG_X2)  # Handle (OUT)
        lr = mu.reg_read(UC_ARM64_REG_X30)  # Return address
        
        # Try to read the PartitionName (UTF-16LE wide string)
        partition_name = ""
        try:
            name_chars = []
            for i in range(0, 256, 2):
                char_bytes = mu.mem_read(x0 + i, 2)
                char_val = struct.unpack("<H", char_bytes)[0]
                if char_val == 0:  # Null terminator in wide string
                    break
                if 0x20 <= char_val <= 0x7E:  # Printable ASCII range
                    name_chars.append(chr(char_val))
                else:
                    break
            partition_name = "".join(name_chars)
        except:
            partition_name = "<unreadable>"
        
        print(f"[FUNCTION] PartitionGetInfo called at 0x{address:X}")
        print(f"       -> PartitionName (X0=0x{x0:X}): '{partition_name}'")
        print(f"       -> BlockIo (X1=0x{x1:X})")
        print(f"       -> Handle (X2=0x{x2:X})")
        print(f"       -> Return Address (LR=0x{lr:X})")
    
    if address == 0x14d18:
        x1 = mu.reg_read(UC_ARM64_REG_X1)  # Argument of interest
        print(f"mylog: {address:X} {x1:X}")
    if address == 0x14d30:
        x0 = mu.reg_read(UC_ARM64_REG_X0)  # Argument of interest
        print(f"mylog: {address:X} {x0:X}")
    if address == 0x571a8:
        w8 = mu.reg_read(UC_ARM64_REG_W8)  # Argument of interest
        print(f"mylog: {address:X} {w8:X}")

    if address == STRNCMP_ADDR: # Strncmp (utf16)
        x0 = mu.reg_read(UC_ARM64_REG_X0)  # Argument of interest
        x1 = mu.reg_read(UC_ARM64_REG_X1)  # Argument of interest
        x2 = 10
        s1 = mu.mem_read(x0, x2 * 2).decode("utf-16-le").split("\x00")[0]
        s2 = mu.mem_read(x1, x2 * 2).decode("utf-16-le").split("\x00")[0]
        print(f"strncmp: {address:X} {s1} {s2} {x2:X}")

def hook_kernel(mu: Uc, address: int, size: int, user_data):
    print(f"KernelCode: {address:X} Code: {mu.mem_read(address, 4).hex()}")

def name_to_register(num: str) -> int:
    if num == "sp":
        return UC_ARM64_REG_SP
    if num == "lr":
        return UC_ARM64_REG_LR
    if num == "pc":
        return UC_ARM64_REG_PC
    if num[0] == "x":
        num = num[1:]
    num = int(num)
    if num < 0 or num > 30:
        raise ValueError(f"Invalid register number: {num}")
    return int(num) + UC_ARM64_REG_X0

def debug_prompt(mu: Uc, address: int):
    """Interactive debug prompt for step execution."""
    global step_mode
    global emulation_paused
    
    while True:
        try:
            cmd = input(f"[0x{address:X}] > ").strip()
        except EOFError:
            # If input is closed (e.g., from pipe), continue normally
            step_mode = False
            emulation_paused = False
            break
        
        if not cmd:
            # Empty command - step to next instruction
            break
        
        if cmd == 'c' or cmd == 'continue':
            # Continue execution (disable step mode)
            step_mode = False
            emulation_paused = False
            break
        
        elif cmd == 's' or cmd == 'step':
            # Single step (keep step_mode on)
            break
        
        elif cmd.startswith('b '):
            # Set breakpoint: b 0x1234
            try:
                bp_addr = int(cmd.split()[1], 16)
                breakpoints.add(bp_addr)
                print(f"  Breakpoint set at 0x{bp_addr:X}")
            except (ValueError, IndexError):
                print(f"  Invalid address format")
        
        elif cmd == 'bl':
            # List breakpoints
            if breakpoints:
                print(f"  Breakpoints: {', '.join(f'0x{bp:X}' for bp in sorted(breakpoints))}")
            else:
                print(f"  No breakpoints set")
        
        elif cmd.startswith('bd '):
            # Delete breakpoint: bd 0x1234
            try:
                bp_addr = int(cmd.split()[1], 16)
                if bp_addr in breakpoints:
                    breakpoints.remove(bp_addr)
                    print(f"  Breakpoint removed at 0x{bp_addr:X}")
                else:
                    print(f"  Breakpoint not found at 0x{bp_addr:X}")
            except (ValueError, IndexError):
                print(f"  Invalid address format")
        
        elif cmd.startswith('x '):
            # Read memory: x 0x80000000 16
            try:
                parts = cmd.split()
                if parts[1].startswith("x"):
                    mem_addr = mu.reg_read(name_to_register(parts[1]))
                else:
                    mem_addr = int(parts[1], 16)
                mem_size = int(parts[2]) if len(parts) > 2 else 16
                mem_data = mu.mem_read(mem_addr, mem_size)
                hex_dump = " ".join(f"{b:02X}" for b in mem_data)
                char_dump = "".join(chr(b) if 32 <= b <= 126 else "." for b in mem_data)
                print(f"  Memory at 0x{mem_addr:X}: {hex_dump} {char_dump}")
            except (ValueError, IndexError):
                print(f"  Invalid format: x <address> [size]")
        
        elif cmd.startswith('r '):
            # Read register: r x0, r x1, etc
            try:
                reg_name = cmd.split()[1].lower()
                val = mu.reg_read(name_to_register(reg_name))
                print(f"  {reg_name} = 0x{val:016X}")
            except (ValueError, IndexError):
                print(f"  Invalid format: r <register>")
        
        elif cmd == 'h' or cmd == 'help':
            print(f"  Commands:")
            print(f"    (empty)     - Step to next instruction")
            print(f"    c/continue  - Continue execution")
            print(f"    s/step      - Single step")
            print(f"    b <addr>    - Set breakpoint at address")
            print(f"    bl          - List all breakpoints")
            print(f"    bd <addr>   - Delete breakpoint at address")
            print(f"    x <addr> [sz] - Read memory at address")
            print(f"    r <reg>     - Read register value")
            print(f"    h/help      - Show this help")
        
        else:
            print(f"  Unknown command: {cmd} (type 'h' for help)")
    

def hook_intr(mu: Uc, intno: int, user_data):
    global _malloc_ptr, _malloc_map
    """Interrupt / exception hook."""
    pc = mu.reg_read(UC_ARM64_REG_PC)
    print(f"[INTR] Interrupt #{intno} at PC=0x{pc:016X}")  # Suppress verbose interrupt logging
    insn = struct.unpack("<I", mu.mem_read(pc, 4))[0]

    if intno == 2:
        # SVC – UEFI or EL1 service call.  We log and skip.
        elr = mu.reg_read(UC_ARM64_REG_PC)
        x0 = mu.reg_read(UC_ARM64_REG_X0)
        x1 = mu.reg_read(UC_ARM64_REG_X1)
        # print(f"  SVC  X0=0x{x0:X}  X1=0x{x1:X}")
        # Return EFI_SUCCESS (0) in X0 and advance past the SVC
        mu.reg_write(UC_ARM64_REG_X0, 0)
    elif intno == 7:
        # BRK – possibly a UEFI service call hitting our RETURN_ADDR stub.
        # Check which BRK it is by reading the instruction.
        
        if insn == 0xD4200000: # BRK #0 (Return catcher)
            print("[EMU]  Return-catcher reached via BRK #0 – emulation complete.")
            mu.emu_stop()
        elif insn == 0xD4200020: # BRK #1 (UEFI Service Stub)
            table_off = mu.reg_read(UC_ARM64_REG_X16)
            svc_type = mu.reg_read(UC_ARM64_REG_X17)
            
            if svc_type == 0:
                svc_name = f"BootService::{EFI_BOOT_SERVICES_NAMES.get(table_off, 'Unknown')}"
            else:
                svc_name = f"RuntimeService::{EFI_RUNTIME_SERVICES_NAMES.get(table_off, 'Unknown')}"
            
            # Print arguments too (X0..X5)
            x0 = mu.reg_read(UC_ARM64_REG_X0)
            x1 = mu.reg_read(UC_ARM64_REG_X1)
            x2 = mu.reg_read(UC_ARM64_REG_X2)
            x3 = mu.reg_read(UC_ARM64_REG_X3)
            x4 = mu.reg_read(UC_ARM64_REG_X4)
            x5 = mu.reg_read(UC_ARM64_REG_X5)
            lr = mu.reg_read(UC_ARM64_REG_X30)
            
            if svc_name != "BootService::HandleProtocol":
                print(f"[UEFI] {svc_name} call at offset 0x{table_off:X} from 0x{lr:X} | Args: 0x{x0:X}, 0x{x1:X}, 0x{x2:X}, 0x{x3:X}, 0x{x4:X}, 0x{x5:X}")
            
            # Special handling for RuntimeService::GetVariable to display variable name
            if svc_type == 1 and table_off == 0x48:  # GetVariable
                # X0 = VariableName (CHAR16* - wide string)
                var_name_ptr = x0
                guid_ptr = x1
                size_ptr = x3
                data_ptr = x4
                try:
                    # Read wide string (CHAR16 = 2 bytes per character)
                    var_name_bytes = bytearray()
                    for i in range(0, 512, 2):  # Read up to 256 characters
                        char_bytes = mu.mem_read(var_name_ptr + i, 2)
                        c1, c2 = struct.unpack("BB", char_bytes)
                        if c1 == 0 and c2 == 0:
                            break  # Null terminator in wide string
                        if c2 == 0 and 0x20 <= c1 <= 0x7E:  # Printable ASCII in low byte
                            var_name_bytes.append(c1)
                        else:
                            break  # Non-ASCII character, stop
                    
                    if var_name_bytes:
                        var_name = var_name_bytes.decode('ascii', errors='ignore')
                        guid_bytes = mu.mem_read(guid_ptr, 16)
                        guid_str = guid_to_str(guid_bytes)
                        if guid_str == "882F8C2B-9646-435F-8DE5-F208FF80C1BD":
                            guid_str = "QCOM"

                        if var_name == "KernelBaseAddr":
                            size = struct.unpack("<Q", mu.mem_read(size_ptr, 8))[0]
                            if size == 8:
                                mu.mem_write(data_ptr, struct.pack("<Q", defines.KERNEL_BASE))
                        if var_name == "KernelSize":
                            size = struct.unpack("<Q", mu.mem_read(size_ptr, 8))[0]
                            if size == 8:
                                mu.mem_write(data_ptr, struct.pack("<Q", defines.KERNEL_SIZE))

                        print(f"       -> [GetVariable] VariableName: '{var_name}' GUID: {guid_str}")
                except UcError as e:
                    print(f"       -> [GetVariable] Could not read VariableName from 0x{var_name_ptr:X}: {e}")
            elif svc_type == 1 and table_off == 0x58:  # SetVariable
                var_name_ptr = x0
                namespace_guid = x1
                length = x3
                data = x4
                try:
                    # Read wide string (CHAR16 = 2 bytes per character)
                    var_name_bytes = bytearray()
                    i = 0
                    while True:
                        char_bytes = mu.mem_read(var_name_ptr + i, 2)
                        if char_bytes == b'\x00\x00':
                            break  # Null terminator in wide string
                        var_name_bytes += char_bytes
                        i += 2
                    
                    if var_name_bytes:
                        var_name = var_name_bytes.decode('utf-16-le', errors='ignore')
                        guid_bytes = mu.mem_read(namespace_guid, 16)
                        guid_str = guid_bytes.hex()
                        data_bytes = mu.mem_read(data, length)
                        print(f"       -> [SetVariable] VariableName: '{var_name}' NamespaceGuid: {guid_str} Data: {data_bytes}")
                except UcError as e:
                    print(f"       -> [SetVariable] Could not read VariableName from 0x{var_name_ptr:X}: {e}")
                

            ret_status = 0
            
            # Handle memory allocation services
            if svc_type == 0 and table_off == 0x40:  # AllocatePool
                pool_type = x0
                size = x1
                buffer_ptr_addr = x2  # Address where we write the allocated pointer
                
                # Allocate from heap, ensuring alignment
                allocated_addr = align_up(_malloc_ptr, 16)  # 16-byte alignment
                _malloc_ptr = allocated_addr + align_up(size, 16)
                
                # Check if we've exceeded heap bounds
                if _malloc_ptr > defines.HEAP_BASE + defines.HEAP_SIZE:
                    print(f"       -> [AllocatePool] Out of heap memory! Requested 0x{size:X} bytes, would exceed 0x{defines.HEAP_BASE + defines.HEAP_SIZE:X}")
                    ret_status = 0x800000000000000C  # EFI_OUT_OF_RESOURCES
                else:
                    _malloc_map[allocated_addr] = size
                    try:
                        mu.mem_write(buffer_ptr_addr, struct.pack("<Q", allocated_addr))
                        print(f"       -> [AllocatePool] Allocated 0x{size:X} bytes at 0x{allocated_addr:X}")
                        ret_status = 0
                    except UcError as e:
                        print(f"       -> [AllocatePool] Failed to write buffer pointer: {e}")
                        ret_status = 0x800000000000000C
            
            elif svc_type == 0 and table_off == 0x48:  # FreePool
                buffer_addr = x0
                if buffer_addr in _malloc_map:
                    size = _malloc_map[buffer_addr]
                    del _malloc_map[buffer_addr]
                    print(f"       -> [FreePool] Freed 0x{size:X} bytes at 0x{buffer_addr:X}")
                    ret_status = 0
                else:
                    print(f"       -> [FreePool] Invalid pointer 0x{buffer_addr:X} (not tracked)")
                    ret_status = 0x800000000000000F  # EFI_INVALID_PARAMETER
            
            elif svc_type == 0 and table_off == 0x38:  # GetMemoryMap
                # X0 = MemoryMapSize (IN/OUT)
                # X1 = MemoryMap (OUT array of EFI_MEMORY_DESCRIPTOR)
                # X2 = MapKey (OUT)
                # X3 = DescriptorSize (OUT)
                # X4 = DescriptorVersion (OUT)
                
                memory_map_size_ptr = x0
                memory_map_ptr = x1
                map_key_ptr = x2
                descriptor_size_ptr = x3
                descriptor_version_ptr = x4
                
                # EFI_MEMORY_DESCRIPTOR: Type(4) + Pad(4) + PhysicalStart(8) + VirtualStart(8) + NumberOfPages(8) + Attribute(8) = 48 bytes
                descriptor_size = 48
                
                # Create a simple memory map with a few entries
                # We'll provide 3 entries: loader code, loader data, and conventional memory for USB buffers
                memory_descriptors = [
                    # Entry 1: Loader code area
                    struct.pack("<I", 0) +  # Type = EfiLoaderCode (0)
                    struct.pack("<I", 0) +  # Padding
                    struct.pack("<Q", 0x00000000) +  # PhysicalStart
                    struct.pack("<Q", 0x00000000) +  # VirtualStart
                    struct.pack("<Q", 0x1000) +  # NumberOfPages (4 MB)
                    struct.pack("<Q", 0x0000000000000003),  # Attribute (UC_PROT_READ|UC_PROT_EXEC)
                    
                    # Entry 2: Loader data area (heap/stack)
                    struct.pack("<I", 1) +  # Type = EfiLoaderData (1)
                    struct.pack("<I", 0) +  # Padding
                    struct.pack("<Q", 0x70000000) +  # PhysicalStart (heap base)
                    struct.pack("<Q", 0x70000000) +  # VirtualStart
                    struct.pack("<Q", 0x20000) +  # NumberOfPages (128 MB for heap/stack)
                    struct.pack("<Q", 0x0000000000000003),  # Attribute
                    
                    # Entry 3: Conventional memory for USB buffers and other allocations
                    struct.pack("<I", 7) +  # Type = EfiConventionalMemory (7)
                    struct.pack("<I", 0) +  # Padding
                    struct.pack("<Q", 0x90000000) +  # PhysicalStart (after stack at 0x7F100000)
                    struct.pack("<Q", 0x90000000) +  # VirtualStart
                    struct.pack("<Q", 0x10000000) +  # NumberOfPages (64GB addressable)
                    struct.pack("<Q", 0x0000000000000001),  # Attribute (EFI_MEMORY_WB - write-back)
                ]
                
                total_descriptor_bytes = len(memory_descriptors) * descriptor_size
                
                try:
                    # Read current MemoryMapSize
                    current_size = struct.unpack("<Q", mu.mem_read(memory_map_size_ptr, 8))[0]
                    
                    if memory_map_ptr == 0 or current_size < total_descriptor_bytes:
                        # First call or buffer too small - return required size
                        ensure_mapped(mu, memory_map_size_ptr, 8)
                        mu.mem_write(memory_map_size_ptr, struct.pack("<Q", total_descriptor_bytes))
                        
                        ensure_mapped(mu, descriptor_size_ptr, 4)
                        mu.mem_write(descriptor_size_ptr, struct.pack("<I", descriptor_size))
                        
                        ensure_mapped(mu, descriptor_version_ptr, 4)
                        mu.mem_write(descriptor_version_ptr, struct.pack("<I", 1))
                        
                        ensure_mapped(mu, map_key_ptr, 4)
                        mu.mem_write(map_key_ptr, struct.pack("<I", 0x12345678))
                        
                        ret_status = 0x8000000000000005  # EFI_BUFFER_TOO_SMALL
                        print(f"       -> [GetMemoryMap] First call: returning required size {total_descriptor_bytes} bytes")
                    else:
                        # Second call - fill the buffer
                        ensure_mapped(mu, memory_map_ptr, total_descriptor_bytes)
                        for i, desc in enumerate(memory_descriptors):
                            mu.mem_write(memory_map_ptr + (i * descriptor_size), desc)
                        
                        ensure_mapped(mu, memory_map_size_ptr, 8)
                        mu.mem_write(memory_map_size_ptr, struct.pack("<Q", total_descriptor_bytes))
                        
                        ensure_mapped(mu, descriptor_size_ptr, 4)
                        mu.mem_write(descriptor_size_ptr, struct.pack("<I", descriptor_size))
                        
                        ensure_mapped(mu, descriptor_version_ptr, 4)
                        mu.mem_write(descriptor_version_ptr, struct.pack("<I", 1))
                        
                        ensure_mapped(mu, map_key_ptr, 4)
                        mu.mem_write(map_key_ptr, struct.pack("<I", 0x12345678))
                        
                        ret_status = 0
                        print(f"       -> [GetMemoryMap] Second call: filled memory map with {len(memory_descriptors)} entries")
                except UcError as e:
                    print(f"       -> [GetMemoryMap] Error: {e}")
                    ret_status = 0x800000000000000F
            
            elif svc_type == 0 and table_off == 0x28:  # AllocatePages
                alloc_type = x0
                mem_type = x1
                num_pages = x2
                memory_ptr_addr = x3  # Address where we write the allocated pointer
                
                page_size = 0x1000
                size = num_pages * page_size
                allocated_addr = align_up(_malloc_ptr, page_size)
                _malloc_ptr = allocated_addr + align_up(size, page_size)
                
                if _malloc_ptr > defines.HEAP_BASE + defines.HEAP_SIZE:
                    print(f"       -> [AllocatePages] Out of heap memory! Requested {num_pages} pages ({size} bytes)")
                    ret_status = 0x800000000000000C  # EFI_OUT_OF_RESOURCES
                else:
                    _malloc_map[allocated_addr] = size
                    try:
                        mu.mem_write(memory_ptr_addr, struct.pack("<Q", allocated_addr))
                        print(f"       -> [AllocatePages] Allocated {num_pages} pages ({size} bytes) at 0x{allocated_addr:X}")
                        ret_status = 0
                    except UcError as e:
                        print(f"       -> [AllocatePages] Failed to write memory pointer: {e}")
                        ret_status = 0x800000000000000C
            
            # Check for LocateProtocol (0x140), LocateHandleBuffer (0x138), OpenProtocol (0x118), HandleProtocol (0x98)
            elif svc_type == 0 and table_off in (0x98, 0x118, 0x138, 0x140):
                # Determine which argument points to the GUID
                if table_off == 0x140:
                    guid_ptr = x0
                elif table_off == 0x138:
                    guid_ptr = x1
                else: # OpenProtocol / HandleProtocol
                    guid_ptr = x1
                    
                x4 = mu.reg_read(UC_ARM64_REG_X4) # For Buffer** in LocateHandleBuffer
                
                try:
                    guid_bytes = bytes(mu.mem_read(guid_ptr, 16))
                    guid_str = guid_to_str(guid_bytes)
                    #print(f"       -> Protocol GUID: {guid_str} (Requested) (From 0x{lr:016X})")
                    
                    if table_off == 0x140: # LocateProtocol
                        proto = PROTOCOL_REGISTRY.get(guid_str.upper())
                        if proto:
                            ret_status = proto.handle_locate_protocol(mu, x2)
                        else:
                            print(f"       -> Protocol {guid_str} not in registry, returning generic mock interface.")
                            mu.mem_write(x2, struct.pack("<Q", MOCK_REGION))
                    
                    elif table_off == 0x138: # LocateHandleBuffer
                        proto = PROTOCOL_REGISTRY.get(guid_str.upper())
                        if proto:
                            ret_status = proto.handle_locate_handle_buffer(mu, x4, x3, allocator=heap_alloc)
                        else:
                            print(f"       -> [LocateHandleBuffer] Protocol {guid_str} not in registry, returning EFI_NOT_FOUND.")
                            ret_status = 0x800000000000000E # EFI_NOT_FOUND
                            
                    elif table_off in (0x98, 0x118): # HandleProtocol or OpenProtocol
                        proto = PROTOCOL_REGISTRY.get(guid_str.upper())
                        if proto:
                            ret_status = proto.handle_open_protocol(mu, x0, x2)
                        else:
                            print(f"       -> [OpenProtocol] Protocol {guid_str} not in registry, providing generic mocked protocol fallback.")
                            mu.mem_write(x2, struct.pack("<Q", MOCK_REGION))
                            ret_status = 0

                except UcError:
                    print(f"       -> Protocol GUID: <unreadable memory at 0x{guid_ptr:X}>")

            elif svc_type == 0 and table_off == 0x160: # CopyMem
                dest = x0
                src = x1
                size = x2
                print(f"       -> [CopyMem] Copying {size} bytes from 0x{src:X} to 0x{dest:X}")
                print(f"       -> [CopyMem] Data: {mu.mem_read(src, size).hex()[0:100]}")
                mu.mem_write(dest, bytes(mu.mem_read(src, size)))
                ret_status = 0
            elif svc_type == 0 and table_off == 0x158: # CalculateCrc32
                data = mu.mem_read(x0, x1)
                crc = binascii.crc32(data)
                mu.mem_write(x2, struct.pack("<I", crc))
                print(f"       -> [CalculateCrc32] Calculating CRC32 for {x1} bytes from 0x{x0:X} -> 0x{crc:X}")
                ret_status = 0
            
            # For unhandled Boot Services, we default to returning EFI_SUCCESS (0), except where overridden above.
            mu.reg_write(UC_ARM64_REG_X0, ret_status)
            
            # Advance PC past BRK instruction to the RET instruction
            mu.reg_write(UC_ARM64_REG_PC, pc + 4)
        elif insn == 0xD4200040: # BRK #2 (Generic Mock Protocol Method Return)
            print("[EMU]  Generic Mock Protocol Method called, returning EFI_SUCCESS.")
            # Return EFI_SUCCESS in X0
            mu.reg_write(UC_ARM64_REG_X0, 0)
            # Advance PC past BRK instruction to the RET instruction
            mu.reg_write(UC_ARM64_REG_PC, pc + 4)
        elif insn == 0xD4200060: # BRK #3 (ReportStatusCode Mock)
            status_code_protocol.handle_call(mu, pc)
            mu.reg_write(UC_ARM64_REG_PC, pc + 4)
        elif insn == 0xD4200080: # BRK #4 (VerifiedBoot Protocol Mock)
            verified_boot_protocol.handle_call(mu, pc)
            mu.reg_write(UC_ARM64_REG_PC, pc + 4)
        elif insn == 0xD42000A0: # BRK #5 (BlockIo.ReadBlocks Mock)
            blockio_protocol.handle_read_blocks(mu)
            mu.reg_write(UC_ARM64_REG_PC, pc + 4)
        elif insn == 0xD42000C0: # BRK #6 (MemCardInfo Protocol)
            mem_card_info_protocol.handle_call(mu, pc)
            mu.reg_write(UC_ARM64_REG_PC, pc + 4)
        elif insn == 0xD4200100: # BRK #8 (RamPartition Protocol)
            ram_partition_protocol.handle_call(mu, pc)
            mu.reg_write(UC_ARM64_REG_PC, pc + 4)
        elif insn == 0xD4200120: # BRK #9 (USB Device Protocol)
            usb_device_protocol.handle_call(mu, pc)
            mu.reg_write(UC_ARM64_REG_PC, pc + 4)
        elif insn == 0xD4200140: # BRK #10 (GOP)
            graphics_output_protocol.handle_call(mu, pc)
            mu.reg_write(UC_ARM64_REG_PC, pc + 4)
        elif insn == 0xD4200160: # BRK #11 (SimpleTextInput)
            simple_text_input_protocol.handle_call(mu, pc)
            mu.reg_write(UC_ARM64_REG_PC, pc + 4)
        elif insn == 0xD4200180: # BRK #12 (SimpleTextOutput)
            simple_text_output_protocol.handle_call(mu, pc)
            mu.reg_write(UC_ARM64_REG_PC, pc + 4)
        elif insn == 0xD42001A0: # BRK #13 (HiiFontProtocol)
            hii_font_protocol.handle_call(mu, pc)
            mu.reg_write(UC_ARM64_REG_PC, pc + 4)
        elif insn == 0xD42001C0: # BRK #14 (Hash2Protocol)
            hash2_protocol.handle_call(mu, pc)
            mu.reg_write(UC_ARM64_REG_PC, pc + 4)
        elif insn == defines.DYNAMIC_HOOK_BRK: # BRK #15 (Dynamic Hook)
            call_dynamic_hook(mu, pc)
            mu.reg_write(UC_ARM64_REG_PC, pc + 4)
        else:
            print(f"  Unhandled BRK instruction: 0x{insn:08X} at PC=0x{pc:016X}")
            try:
                nearby = mu.mem_read(pc - 16, 32)
                print(f"  Memory around PC: {nearby.hex()}")
            except:
                pass
            mu.emu_stop()
    elif intno == 13:
        print(f"int 13: {insn:08X}")
        mu.reg_write(UC_ARM64_REG_PC, pc + 4)
        mu.reg_write(UC_ARM64_REG_X0, -1)
        if insn == 0xd4000003:
            print(f"SMC called: {mu.reg_read(UC_ARM64_REG_X0):X}")
    else:
        print(f"  Unhandled interrupt {intno} at PC=0x{mu.reg_read(UC_ARM64_REG_PC):016X} stopping.")
        mu.emu_stop()


def hook_mem_unmapped(mu: Uc, access, address: int, size: int,
                      value: int, user_data):
    """Handle unmapped memory accesses by dynamically mapping pages."""
    if address == 0:
        print(f"\n[CRITICAL] Branch to NULL at PC=0x{mu.reg_read(UC_ARM64_REG_PC):016X} (LR=0x{mu.reg_read(UC_ARM64_REG_LR):016X})")
        mu.emu_stop()
        return False
    
    access_str = {
        UC_MEM_READ_UNMAPPED:  "READ",
        UC_MEM_WRITE_UNMAPPED: "WRITE",
        UC_MEM_FETCH_UNMAPPED: "FETCH",
    }.get(access, "UNKNOWN")

    pc = mu.reg_read(UC_ARM64_REG_PC)
    print(f"[MEM]  Unmapped {access_str} at 0x{address:016X} "
          f"(size={size}, value=0x{value:X}) PC=0x{pc:016X}")

    if access == UC_MEM_FETCH_UNMAPPED and address == RETURN_ADDR:
        # The emulated code tried to branch to our return catcher.
        print("[EMU]  Return-catcher reached – emulation complete.")
        mu.emu_stop()
        return True

    # Auto-map a 4 KB page so emulation can continue.
    page = address & ~(PAGE_SIZE - 1)
    try:
        mu.mem_map(page, PAGE_SIZE, UC_PROT_ALL)
        print(f"       -> Mapped page 0x{page:016X}")
        return True
    except UcError:
        print(f"       -> FAILED to map page 0x{page:016X}")
        return False


def hook_mem_invalid(mu: Uc, access, address: int, size: int,
                     value: int, user_data):
    """Handle other invalid memory accesses (e.g., permission faults)."""
    access_str = {
        UC_MEM_READ_PROT:  "READ_PROT",
        UC_MEM_WRITE_PROT: "WRITE_PROT",
        UC_MEM_FETCH_PROT: "FETCH_PROT",
    }.get(access, f"?({access})")

    pc = mu.reg_read(UC_ARM64_REG_PC)
    print(f"[MEM]  Invalid {access_str} at 0x{address:016X} "
          f"(size={size}) PC=0x{pc:016X}")
    mu.emu_stop()
    return False


def dump_regs(mu: Uc):
    """Print general-purpose registers."""
    print("\n===== Register dump =====")
    for i in range(31):
        reg_id = UC_ARM64_REG_X0 + i
        val = mu.reg_read(reg_id)
        end = "\n" if (i % 4 == 3) else "  "
        print(f"  X{i:<2d}=0x{val:016X}", end=end)
    print()
    pc = mu.reg_read(UC_ARM64_REG_PC)
    sp = mu.reg_read(UC_ARM64_REG_SP)
    lr = mu.reg_read(UC_ARM64_REG_LR)
    print(f"  PC =0x{pc:016X}  SP =0x{sp:016X}  LR =0x{lr:016X}")
    print("=========================\n")


def dump_stack_trace(mu: Uc):
    """Scan the stack to find return addresses (Heuristic Stack Scanning)."""
    print("\n===== Heuristic Stack Trace =====")
    pc = mu.reg_read(UC_ARM64_REG_PC)
    lr = mu.reg_read(UC_ARM64_REG_LR)
    sp = mu.reg_read(UC_ARM64_REG_SP)
    
    print(f"  [0] PC: 0x{pc:016X} (Current)")
    
    depth = 1
    # Check if current LR points back inside our PE
    if IMAGE_BASE <= lr < IMAGE_BASE + IMAGE_SIZE:
        print(f"  [{depth}] LR: 0x{lr:016X} (Return Address)")
        depth += 1
    else:
        print(f"  [ ] LR: 0x{lr:016X} (Out of bounds)")
    
    # Align SP to 8 bytes and scan upwards towards STACK_BASE
    current_addr = sp & ~7
    while current_addr < STACK_BASE:
        try:
            val = struct.unpack("<Q", mu.mem_read(current_addr, 8))[0]
            # If the value on the stack points to our PE code section, it's highly likely a return address!
            if IMAGE_BASE <= val < IMAGE_BASE + IMAGE_SIZE:
                print(f"  [{depth}] Stack-> 0x{val:016X} (at SP+0x{current_addr - sp:04X})")
                depth += 1
        except UcError:
            print(f"      <Failed to read stack at 0x{current_addr:016X}>")
            break
            
        current_addr += 8
            
    print("=================================\n")

def extract_pe(filename: str):
    with open(filename, "rb") as f:
        magic = f.read(4)
        if magic == b"\x7FELF":
            f.seek(0x1078)
            compressed_data = f.read()
            try:
                decompressed_data = lzma.decompress(compressed_data, format=lzma.FORMAT_ALONE)
                offset = 0xb8
                if decompressed_data[offset:offset+2] != b"MZ":
                    print("FATAL: Extract ok, but internal data is not PE")
                    exit(2)

                return decompressed_data[offset:]
            except lzma.LZMAError as e:
                print(f"FATAL: {e}")
        else:
            f.seek(0)
            return f.read()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global args
    parser = argparse.ArgumentParser()
    parser.add_argument("pe", help="Path to PE file", default="abl.pe", nargs="?")
    parser.add_argument("--feed-cmd", action="append", help="Feed fastboot command")
    parser.add_argument("--chip-id", type=int, default=0x26a, help="Chip ID")
    parser.add_argument("--chip-version", type=int, default=0x10000, help="Chip version")
    parser.add_argument("--reset-reason", type=int, default=0x0, help="Reset reason. 0: Normal, 1: Recovery, 2: Fastboot, ...")
    args = parser.parse_args()

    if args.feed_cmd:
        for cmd in args.feed_cmd:
            feed_fastboot_cmd(cmd)

    pe_data = extract_pe(args.pe)
    print(f"[*] Trace mode: {'ON' if _trace_enabled else 'OFF'}  "
          f"(set EMU_TRACE=1 to enable)")

    # -----------------------------------------------------------------------
    # 1. Create Unicorn instance (AArch64)
    # -----------------------------------------------------------------------
    mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)

    # -----------------------------------------------------------------------
    # 2. Load PE into emulated memory
    # -----------------------------------------------------------------------
    entry_point, image_base = load_pe(mu, pe_data)

    # -----------------------------------------------------------------------
    # 3. Set up stack
    # -----------------------------------------------------------------------
    mu.mem_map(defines.STACK_BASE - defines.STACK_SIZE, defines.STACK_SIZE, UC_PROT_ALL)
    sp = defines.STACK_BASE - 0x10  # 16-byte aligned
    mu.reg_write(UC_ARM64_REG_SP, sp)

    # -----------------------------------------------------------------------
    # 4. Set up heap region (for dynamic mapping by hooks)
    # -----------------------------------------------------------------------
    mu.mem_map(defines.HEAP_BASE, defines.HEAP_SIZE, UC_PROT_ALL)

    # -----------------------------------------------------------------------
    # 5. Set up UEFI stubs
    # -----------------------------------------------------------------------
    setup_uefi_tables(mu, args.chip_id, args.chip_version)

    set_reset_reason(args.reset_reason)

    # -----------------------------------------------------------------------
    # 6. Prepare a return-catcher page with BRK #0
    # -----------------------------------------------------------------------
    ret_page = defines.RETURN_ADDR & ~(defines.PAGE_SIZE - 1)
    # BRK #0 encoding: 0xD4200000
    mu.mem_write(defines.RETURN_ADDR, struct.pack("<I", 0xD4200000))

    # -----------------------------------------------------------------------
    # 7. Set up UEFI entry-point convention:
    #    X0 = EFI_HANDLE ImageHandle
    #    X1 = EFI_SYSTEM_TABLE *SystemTable
    #    LR = RETURN_ADDR (so RET lands on our catcher)
    # -----------------------------------------------------------------------
    mu.reg_write(UC_ARM64_REG_X0, EFI_IMAGE_HANDLE)
    mu.reg_write(UC_ARM64_REG_X1, defines.EFI_SYSTEM_TABLE_ADDR)
    mu.reg_write(UC_ARM64_REG_LR, defines.RETURN_ADDR)

    # -----------------------------------------------------------------------
    # 8. Install hooks
    # -----------------------------------------------------------------------
    if _trace_enabled:
        mu.hook_add(UC_HOOK_CODE, hook_code)
    mu.hook_add(UC_HOOK_INTR, hook_intr)
    mu.hook_add(UC_HOOK_MEM_UNMAPPED, hook_mem_unmapped)
    mu.hook_add(UC_HOOK_MEM_READ_PROT | UC_HOOK_MEM_WRITE_PROT |
                UC_HOOK_MEM_FETCH_PROT, hook_mem_invalid)

    def hook_log_15ec(mu: Uc, address: int, size: int, user_data):
        arg0 = mu.reg_read(UC_ARM64_REG_X0)
        arg1_ptr = mu.reg_read(UC_ARM64_REG_X1)
        arg2 = mu.reg_read(UC_ARM64_REG_X2)
        arg3 = mu.reg_read(UC_ARM64_REG_X3)
        arg4 = mu.reg_read(UC_ARM64_REG_X4)
        arg5 = mu.reg_read(UC_ARM64_REG_X5)
        
        def read_string(ptr: int) -> str:
            if ptr == 0 or ptr < 0x1000:
                return ""
            try:
                # Try reading ASCII
                s_bytes = bytearray()
                for i in range(256):
                    c = mu.mem_read(ptr + i, 1)[0]
                    if c == 0:
                        break
                    if 0x20 <= c <= 0x7E:  # printable ASCII
                        s_bytes.append(c)
                    else:
                        
                        # Not a pure ASCII print-able string, maybe UCS-2/UTF-16?
                        # Let's just try to read wide string as well
                        if i == 1 and s_bytes and c == 0:
                            pass # potentially wide char "x\x00"
                        else:
                            return ""
                if len(s_bytes) >= 2:
                    return s_bytes.decode('ascii')
                
                # Try UTF-16 LE
                s_bytes = bytearray()
                for i in range(0, 512, 2):
                    c1, c2 = struct.unpack("BB", mu.mem_read(ptr + i, 2))
                    if c1 == 0 and c2 == 0:
                        break
                    if c2 == 0 and 0x20 <= c1 <= 0x7E:
                        s_bytes.append(c1)
                    else:
                        return ""
                if len(s_bytes) >= 2:
                    return s_bytes.decode('ascii')
            except UcError:
                pass
            return ""

        arg2_s = read_string(arg2)
        arg3_s = read_string(arg3)
        arg4_s = read_string(arg4)
        arg5_s = read_string(arg5)

        args_str_parts = []
        for i, (val, s) in enumerate([(arg2, arg2_s), (arg3, arg3_s), (arg4, arg4_s), (arg5, arg5_s)]):
            if s:
                args_str_parts.append(f"0x{val:X}('{s}')")
            else:
                args_str_parts.append(f"0x{val:X}")

        try:
            s_bytes = bytearray()
            for i in range(1024):
                c = mu.mem_read(arg1_ptr + i, 1)[0]
                if c == 0:
                    break
                s_bytes.append(c)
            arg1_str = s_bytes.decode('utf-8', errors='replace').strip()
        except UcError:
            arg1_str = "<unreadable>"
        
        # Format and print the log message
        processed_fmt = process_format_string(mu, arg1_str, [arg2, arg3, arg4, arg5])
        lr = mu.reg_read(UC_ARM64_REG_LR)
        print(f"[LOG 15ec][{lr:X}] Level: 0x{arg0:x} | {processed_fmt}")
        
        # Skip the rest of this debug function and return immediately
        lr = mu.reg_read(UC_ARM64_REG_LR)
        mu.reg_write(UC_ARM64_REG_PC, lr)

    hook_addr = image_base + 0x15EC
    #mu.hook_add(UC_HOOK_CODE, hook_log_15ec, begin=hook_addr, end=hook_addr)

    def hook_getblkiohandles(mu: Uc, address: int, size: int, user_data):
        x0 = mu.reg_read(UC_ARM64_REG_X0)  # SelectionAttrib
        x1 = mu.reg_read(UC_ARM64_REG_X1)  # FilterData pointer
        x2 = mu.reg_read(UC_ARM64_REG_X2)  # HandleInfoPtr pointer
        x3 = mu.reg_read(UC_ARM64_REG_X3)  # MaxBlkIopCnt pointer
        lr = mu.reg_read(UC_ARM64_REG_LR)  # Return address
        
        print(f"\n[FUNC] GetBlkIOHandles called from 0x{lr:X}")
        print(f"       SelectionAttrib (X0): 0x{x0:X}")
        print(f"       FilterData (X1):      0x{x1:016X}")
        print(f"       HandleInfoPtr (X2):   0x{x2:016X}")
        print(f"       MaxBlkIopCnt (X3):    0x{x3:016X}")
        
        # Try to read MaxBlkIopCnt value
        try:
            max_cnt = struct.unpack("<I", mu.mem_read(x3, 4))[0]
            print(f"       *MaxBlkIopCnt (value): {max_cnt}")
        except UcError:
            print(f"       *MaxBlkIopCnt: <unreadable>")
        
        # Try to read FilterData structure if not NULL
        if x1 != 0:
            try:
                # PartiSelectFilter is a structure with:
                # - RootDeviceType (pointer to GUID)
                # - PartitionType (pointer to GUID)
                # - PartitionLabel (pointer to CHAR16)
                # - VolumeName (pointer to CHAR8)
                filter_data = mu.mem_read(x1, 32)
                root_dev_type = struct.unpack("<Q", filter_data[0:8])[0]
                partition_type = struct.unpack("<Q", filter_data[8:16])[0]
                volume_name = struct.unpack("<Q", filter_data[16:24])[0]
                partition_label = struct.unpack("<Q", filter_data[24:32])[0]
                
                print(f"       FilterData contents:")
                print(f"         RootDeviceType (ptr):    0x{root_dev_type:016X}")
                print(f"         PartitionType (ptr):     0x{partition_type:016X}")
                print(f"         VolumeName (ptr):        0x{volume_name:016X}")
                print(f"         PartitionLabel (ptr):    0x{partition_label:016X}")
                
                # Read RootDeviceType GUID if pointer is not NULL
                if root_dev_type != 0:
                    try:
                        guid_bytes = bytes(mu.mem_read(root_dev_type, 16))
                        print(f"           RootDeviceType GUID: {guid_to_str(guid_bytes)}")
                    except UcError:
                        print(f"           RootDeviceType GUID: <unreadable at 0x{root_dev_type:016X}>")
                
                # Read PartitionType GUID if pointer is not NULL
                if partition_type != 0:
                    try:
                        guid_bytes = bytes(mu.mem_read(partition_type, 16))
                        print(f"           PartitionType GUID: {guid_to_str(guid_bytes)}")
                    except UcError:
                        print(f"           PartitionType GUID: <unreadable at 0x{partition_type:016X}>")
                
                # Read PartitionLabel string if pointer is not NULL (wide string)
                if partition_label != 0:
                    try:
                        label_bytes = bytearray()
                        for i in range(0, 256, 2):
                            c1, c2 = struct.unpack("BB", mu.mem_read(partition_label + i, 2))
                            if c1 == 0 and c2 == 0:
                                break
                            if c2 == 0 and 0x20 <= c1 <= 0x7E:
                                label_bytes.append(c1)
                            else:
                                break
                        if label_bytes:
                            print(f"           PartitionLabel: '{label_bytes.decode('ascii', errors='ignore')}'")
                    except UcError:
                        print(f"           PartitionLabel: <unreadable at 0x{partition_label:016X}>")
                
                # Read VolumeName string if pointer is not NULL (ASCII string)
                if volume_name != 0:
                    try:
                        vol_bytes = bytearray()
                        for i in range(256):
                            c = mu.mem_read(volume_name + i, 1)[0]
                            if c == 0:
                                break
                            if 0x20 <= c <= 0x7E:
                                vol_bytes.append(c)
                            else:
                                break
                        if vol_bytes:
                            print(f"           VolumeName: '{vol_bytes.decode('ascii', errors='ignore')}'")
                    except UcError:
                        print(f"           VolumeName: <unreadable at 0x{volume_name:016X}>")
            except UcError:
                print(f"       FilterData: <unreadable>")

    getblkiohandles_addr = image_base + 0xADB4
    mu.hook_add(UC_HOOK_CODE, hook_getblkiohandles, begin=getblkiohandles_addr, end=getblkiohandles_addr)
    mu.hook_add(UC_HOOK_CODE, hook_getblkiohandles, begin=0x000149c0, end=0x000149c0)

    #mu.hook_add(UC_HOOK_CODE, hook_code, begin=STRNCMP_ADDR, end=STRNCMP_ADDR)

    mu.mem_map(defines.KERNEL_BASE, defines.KERNEL_SIZE)
    # We soon die after kernel is executed, but still some codes are emulated. This hook traces all kernel codes.
    # Dies at: 1ca93ac: d5181000      msr     SCTLR_EL1, x0
    mu.hook_add(UC_HOOK_CODE, hook_kernel, begin=defines.KERNEL_BASE, end=defines.KERNEL_BASE + defines.KERNEL_SIZE)

    set_simple_hook(mu, 0xe4c0, lambda mu, address, size, user_data: print(f"0x{address:x}: Compare {mu.reg_read(UC_ARM64_REG_X8).to_bytes(4, 'little').decode('utf-8', errors='ignore')} {mu.reg_read(UC_ARM64_REG_X10).to_bytes(4, 'little').decode('utf-8', errors='ignore')}"))

    # -----------------------------------------------------------------------
    # 9. Initialize debugging (breakpoints from environment variable)
    # -----------------------------------------------------------------------
    global breakpoints, step_mode
    bp_env = os.environ.get("BREAKPOINTS", "")
    if bp_env:
        for bp_str in bp_env.split(","):
            try:
                bp_addr = int(bp_str.strip(), 16)
                breakpoints.add(bp_addr)
                mu.hook_add(UC_HOOK_CODE, hook_code, begin=bp_addr, end=bp_addr)
                print(f"[DEBUG] Breakpoint set at 0x{bp_addr:X}")
            except ValueError:
                print(f"[DEBUG] Invalid breakpoint address: {bp_str}")
    
    step_env = os.environ.get("STEP", "0")
    if step_env == "1":
        step_mode = True
        print(f"[DEBUG] Step execution mode enabled")
    
    # -----------------------------------------------------------------------
    # 10. Start emulation
    # -----------------------------------------------------------------------
    print(f"\n[*] Starting emulation at 0x{entry_point:016X} ...")
    print(f"    SP  = 0x{sp:016X}")
    print(f"    X0  = 0x{EFI_IMAGE_HANDLE:016X}  (ImageHandle)")
    print(f"    X1  = 0x{defines.EFI_SYSTEM_TABLE_ADDR:016X}  (SystemTable)")
    print(f"    LR  = 0x{defines.RETURN_ADDR:016X}  (return catcher)")
    print()

    try:
        mu.emu_start(entry_point, defines.RETURN_ADDR, count=MAX_INSN)
    except UcError as e:
        pc = mu.reg_read(UC_ARM64_REG_PC)
        print(f"\n[!] Emulation error at PC=0x{pc:016X}: {e}")

    # -----------------------------------------------------------------------
    # 10. Post-emulation state
    # -----------------------------------------------------------------------
    print(f"\n[*] Emulation finished after {_insn_count} instructions.")
    dump_regs(mu)

    # Return value (EFI_STATUS) is in X0
    x0 = mu.reg_read(UC_ARM64_REG_X0)
    if x0 == 0:
        print("[*] EFI_STATUS = EFI_SUCCESS (0x0)")
    else:
        print(f"[*] EFI_STATUS = 0x{x0:016X}")


if __name__ == "__main__":
    main()
