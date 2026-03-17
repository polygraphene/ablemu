import struct
import os
from unicorn.arm64_const import *
from unicorn import UcError
from utils import (align_up, allocate_mock, allocate_mock_bytes,
ensure_mapped, register_dynamic_hook, read_string, hexdump, guid_to_str)
from format_string import process_format_string
import defines
import queue
from partitions import PartitionList
import hashlib

DISK_HANDLE = 0xDE000001
#DISK_HANDLE = struct.unpack("<I", b"ufs ")[0]
MEMCARD_INFO_HANDLE = 0xDE000001
HANDLE_INDEX_0 = 0xDE000003
# MEDIA_DISK = struct.unpack("<I", b"VBLK")[0]
MEDIA_DISK = 1

fastboot_cmds = []
reset_reason = 0


def feed_fastboot_cmd(cmd):
    fastboot_cmds.append(cmd)

def set_reset_reason(reason):
    global reset_reason
    reset_reason = reason

class Protocol():
    def __init__(self, guid=None):
        self._guid = guid
        self.addr = 0

    def guid(self):
        return self._guid

    def handle_locate_handle_buffer(self, mu, buffer_ptr_ptr_addr, count_ptr_addr, allocator=None):
        return defines.EFI_NOT_FOUND

    def hook_addr(self):
        return []
    
    def generate_hook_funcs(self, mu, prefix):
        self.addr = allocate_mock(len(prefix) + 8 * len(self.funcs))
        self.stub_addr = allocate_mock(8 * len(self.funcs))
        
        mu.mem_write(self.addr, prefix)
        
        for i in range(len(self.funcs)):
            stub_addr = self.stub_addr + (i * 8)
            register_dynamic_hook(stub_addr, self, i)
            mu.mem_write(stub_addr, defines.DYNAMIC_HOOK_STUB)
            mu.mem_write(self.addr + len(prefix) + (i * 8), struct.pack("<Q", stub_addr))

    def handle_locate_protocol(self, mu, interface_ptr_ptr_addr):
        if self.addr != 0:
            print(f"       -> [LocateProtocol] Found requests for {self.__class__.__name__}, returning mock interface.")
            mu.mem_write(interface_ptr_ptr_addr, struct.pack("<Q", self.addr))
            return 0
        return defines.EFI_NOT_FOUND

    def handle_open_protocol(self, mu, handle, interface_ptr_ptr_addr):
        if self.addr != 0:
            print(f"       -> [OpenProtocol] Returning mocked {self.__class__.__name__} Protocol.")
            mu.mem_write(interface_ptr_ptr_addr, struct.pack("<Q", self.addr))
            return 0
        return defines.EFI_NOT_FOUND



class BlockIoProtocol(Protocol):
    def __init__(self, partition_list: PartitionList):
        super().__init__(defines.EFI_BLOCK_IO_PROTOCOL_GUID)
        self.media_disk_addr = 0
        self.protocol_disk_addr = 0
        self.medias_addr = []
        self.protocols_addr = []
        self.read_stub_addr = 0
        self.partition_list = partition_list
        
    def setup(self, mu, mock_func_addr):
        """Setup EFI_BLOCK_IO_PROTOCOL for disk, devinfo, and frp partitions."""
        self.protocol_disk_addr = allocate_mock(0x80)
        self.media_disk_addr = allocate_mock(0x80)

        for partition in self.partition_list:
            self.protocols_addr.append(allocate_mock(0x80))
            self.medias_addr.append(allocate_mock(0x80))
        self.read_stub_addr = allocate_mock(16)

        # Write a custom stub for ReadBlocks (BRK #5)
        # BRK #5 (0xD42000A0), RET (0xD65F03C0)
        mu.mem_write(self.read_stub_addr, struct.pack("<II", 0xD42000A0, 0xD65F03C0))
        
        # Setup EFI_BLOCK_IO_MEDIA for disk, devinfo, and frp partitions
        # Disk (entire device) - Media ID 1
        disk_media_data = struct.pack("<IbbbbbxxxIIxxxxQQII", MEDIA_DISK, 0, 1, 0, 0, 0, defines.BLOCK_SIZE, 1, self.partition_list.total_lba - 1, 0, 1, 1)
        mu.mem_write(self.media_disk_addr, disk_media_data)
        
        for i, partition in enumerate(self.partition_list):
            devinfo_media_data = struct.pack("<IbbbbbxxxIIxxxxQQII", 2 + i, 0, 1, 1, 0, 0, defines.BLOCK_SIZE, 1, partition["ending_lba"] - partition["starting_lba"], 0, 1, 1)
            mu.mem_write(self.medias_addr[i], devinfo_media_data)
            
        # Setup EFI_BLOCK_IO_PROTOCOL for disk
        disk_proto_data = struct.pack("<QQQQQQ", 0x0000000000010000, self.media_disk_addr, mock_func_addr, self.read_stub_addr, mock_func_addr, mock_func_addr)
        mu.mem_write(self.protocol_disk_addr, disk_proto_data)
        
        for i, partition in enumerate(self.partition_list):
            # Setup EFI_BLOCK_IO_PROTOCOL for partitions
            proto_data = struct.pack("<QQQQQQ", 0x0000000000010000, self.medias_addr[i], mock_func_addr, self.read_stub_addr, mock_func_addr, mock_func_addr)
            mu.mem_write(self.protocols_addr[i], proto_data)

    def handle_locate_handle_buffer(self, mu, buffer_ptr_ptr_addr, count_ptr_addr, allocator=None):
        if allocator is None:
            return 0x800000000000000C  # EFI_OUT_OF_RESOURCES
        
        print("       -> [LocateHandleBuffer] Returning disk + partitions BlockIo handles.")
        handle_array_size = 8 * (1 + len(self.partition_list))
        allocated_handle_addr = allocator(handle_array_size)
        
        # Write the three handles to the allocated array
        mu.mem_write(allocated_handle_addr + 0, struct.pack("<Q", DISK_HANDLE))
        for i, partition in enumerate(self.partition_list):
            mu.mem_write(allocated_handle_addr + 8 + i * 8, struct.pack("<Q", HANDLE_INDEX_0 + i))
        # Write number of handles to count_ptr_addr
        mu.mem_write(count_ptr_addr, struct.pack("<Q", 1 + len(self.partition_list)))
        # Write the buffer pointer to buffer_ptr_ptr_addr
        mu.mem_write(buffer_ptr_ptr_addr, struct.pack("<Q", allocated_handle_addr))
        print(f"       -> [LocateHandleBuffer] Allocated handle array at 0x{allocated_handle_addr:X} with {1 + len(self.partition_list)} handles")
        return 0

    def handle_open_protocol(self, mu, handle, interface_ptr_ptr_addr):
        if handle == DISK_HANDLE:
            blockio_addr = self.protocol_disk_addr
            #print(f"       -> [OpenProtocol] Returning BlockIo Protocol for disk handle 0x{handle:X} at 0x{blockio_addr:X}")
        else:
            partition_index = handle - HANDLE_INDEX_0
            blockio_addr = self.protocols_addr[partition_index]
            #print(f"       -> [OpenProtocol] Returning BlockIo Protocol for partition {self.partition_list[partition_index]["partition_name"]} handle 0x{handle:X} at 0x{blockio_addr:X}")
        
        # Add some debug info as in original emu.py
        try:
            device_path_data = mu.mem_read(blockio_addr, 0x100)
            media_addr = struct.unpack("<Q", device_path_data[8:16])[0]
            #print(f"       -> Block IO Media at 0x{media_addr:X}")
        except:
            pass
            
        mu.mem_write(interface_ptr_ptr_addr, struct.pack("<Q", blockio_addr))
        return 0

    def handle_read_blocks(self, mu):
        """Implementation of BlockIo.ReadBlocks (BRK #5)."""
        # Args: X0 = This, X1 = MediaId, X2 = LBA, X3 = BufferSize, X4 = Buffer
        this_ptr = mu.reg_read(UC_ARM64_REG_X0)
        media_id = mu.reg_read(UC_ARM64_REG_X1)
        lba      = mu.reg_read(UC_ARM64_REG_X2)
        buf_size = mu.reg_read(UC_ARM64_REG_X3)
        buf_ptr  = mu.reg_read(UC_ARM64_REG_X4)
        
        print(f"[UEFI] BlockIo::ReadBlocks | MediaId: {media_id}, LBA: 0x{lba:X}, Size: 0x{buf_size:X} into 0x{buf_ptr:X}")
        try:
            if media_id == MEDIA_DISK:
                print("Warning: Disk whole partition read is not supported.")
                mu.reg_write(UC_ARM64_REG_X0, 0)
                return

            partition_index = media_id - 2
            offset = lba * defines.BLOCK_SIZE
            path = self.partition_list[partition_index]["path"]

            read_data = None
            if os.path.isfile(path):
                try:
                    with open(path, "rb") as f:
                        f.seek(offset)
                        read_data = f.read(buf_size)
                        if len(read_data) < buf_size:
                            read_data += b"\x00" * (buf_size - len(read_data))
                        print(f"       -> [BlockIo] Read {len(read_data)} bytes from {path}@0x{offset:X}")
                except Exception as e:
                    print(f"       -> [BlockIo] Error reading {path}: {e}")
                    read_data = None

            if read_data is None:
                read_data = b"\x00" * buf_size

            ensure_mapped(mu, buf_ptr, len(read_data))
            mu.mem_write(buf_ptr, read_data)
        except UcError:
            pass
        
        # Return EFI_SUCCESS (0) in X0
        mu.reg_write(UC_ARM64_REG_X0, 0)

class DevicePathProtocol(Protocol):
    def __init__(self, partition_list: PartitionList):
        super().__init__(defines.EFI_DEVICE_PATH_PROTOCOL_GUID)
        self.device_path_addr = 0
        self.partition_device_path_addr = []
        self.partition_list = partition_list

    def create_device_path(self, partition_number: int, partition_start: int, partition_size: int) -> bytes:
        """Create a device path for a partition."""
        # VENDOR_DEVICE_PATH: Type=0x02 (HARDWARE), SubType=0x04 (HW_VENDOR_DP)
        vendor_dp = struct.pack("<BBHIHH8B",
            0x01,           # Type = HARDWARE_DEVICE_PATH
            0x04,           # SubType = HW_VENDOR_DP
            0x0014,         # Length = 20 bytes (little-endian)
            # gEfiUfsLU0Guid =                      { 0x860845c1, 0xbe09, 0x4355, { 0x8b, 0xc1, 0x30, 0xd6, 0x4f, 0xf8, 0xe6, 0x3a } }
            0x860845c1, 0xbe09, 0x4355, 0x8b, 0xc1, 0x30, 0xd6, 0x4f, 0xf8, 0xe6, 0x3a
        )
        # HDD_DEVICE_PATH for this partition
        hdd_dp = struct.pack("<BBHIQQ16BBB",
            0x04,           # Type = MEDIA_DEVICE_PATH
            0x01,           # SubType = MEDIA_HARDDRIVE_DP
            0x002a,         # Length = 0x2a bytes
            partition_number,  # PartitionNumber
            partition_start,   # PartitionStart LBA
            partition_size,    # PartitionSize in LBA
            # Signature (16 bytes)
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x2,  # MBRType (GPT)
            0x0   # SignatureType
        )
        # End of Device Path node
        end_of_path = struct.pack("<BBH", 0x7F, 0xFF, 0x0004)
        return vendor_dp + hdd_dp + end_of_path

    def setup(self, mu):
        disk_dp = self.create_device_path(0, 0, self.partition_list.total_lba)                # Disk (entire device)
        self.device_path_addr = allocate_mock_bytes(mu, disk_dp)

        for i, partition in enumerate(self.partition_list.partition_list):
            partition_dp = self.create_device_path(i + 1, partition["starting_lba"], partition["size"] // defines.BLOCK_SIZE)
            partition_dp_addr = allocate_mock_bytes(mu, partition_dp)
            self.partition_device_path_addr.append(partition_dp_addr)
        
        print(f"[INIT] Created device paths: disk at 0x{self.device_path_addr:X}, devinfo at 0x{self.device_path_addr + 0x80:X}, frp at 0x{self.device_path_addr + 0x100:X}")

    def handle_open_protocol(self, mu, handle, interface_ptr_ptr_addr):
        if handle == DISK_HANDLE:
            device_path_addr = self.device_path_addr
            # print(f"       -> [OpenProtocol] Returning EFI_DEVICE_PATH_PROTOCOL for disk handle 0x{handle:X} at 0x{device_path_addr:X}")
        else:
            partition_index = handle - HANDLE_INDEX_0
            device_path_addr = self.partition_device_path_addr[partition_index]
            # print(f"       -> [OpenProtocol] Returning EFI_DEVICE_PATH_PROTOCOL for partition handle 0x{handle:X} at 0x{device_path_addr:X}")
        
        mu.mem_write(interface_ptr_ptr_addr, struct.pack("<Q", device_path_addr))
        return 0

class PartitionEntryProtocol(Protocol):
    def __init__(self, partition_list: PartitionList):
        super().__init__(defines.EFI_PARTITION_ENTRY_PROTOCOL_GUID)
        self.disk_addr = 0
        self.partitions_addr = []
        self.partition_list = partition_list

    def create_partition_entry(self, partition_name_str: str, starting_lba: int, ending_lba: int) -> bytes:
        """Create a single EFI partition entry."""
        guid_seed = hash(partition_name_str) & 0xFFFFFFFF
        partition_type_guid = struct.pack("<IHH8B", guid_seed, 0x0000, 0x0000, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
        
        # Generate unique GUID based on partition name
        unique_partition_guid = struct.pack("<IHH8B", guid_seed, 0x1234, 0x5678, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0)
        
        # Attributes (0 = no special attributes)
        attributes = 0
        
        # PartitionName in UTF-16LE, padded to 72 bytes (36 CHAR16 entries)
        partition_name_utf16 = partition_name_str.encode('utf-16le')
        partition_name = partition_name_utf16 + b'\x00\x00' * (36 - len(partition_name_str))
        
        # Construct the full partition entry
        ret = (partition_type_guid + unique_partition_guid + 
                struct.pack("<QQQ", starting_lba, ending_lba, attributes) + 
                partition_name)
        print(f"[INIT] Created partition entry for '{partition_name_str}': StartLBA=0x{starting_lba:X}, EndLBA=0x{ending_lba:X}, len={len(ret)} bytes")
        return ret

    def setup(self, mu):
        """Setup EFI_PARTITION_ENTRY structures for multiple partitions."""
        self.disk_addr  = allocate_mock(128)
        for partition in self.partition_list.get_partition_list():
            self.partitions_addr.append(allocate_mock(128))

        # Create partition entries: disk (entire device), devinfo, and frp
        disk_entry = self.create_partition_entry("Disk", 0, self.partition_list.total_lba - 1)
        for partition, partition_addr in zip(self.partition_list.get_partition_list(), self.partitions_addr):
            partition_entry = self.create_partition_entry(partition["partition_name"], partition["starting_lba"], partition["ending_lba"])
            mu.mem_write(partition_addr, partition_entry)

        # Write partition entries
        mu.mem_write(self.disk_addr, disk_entry)

        print(f"[INIT] Created partition entries: disk at 0x{self.disk_addr:X}, partitions at 0x{self.partitions_addr}")

    def handle_locate_handle_buffer(self, mu, buffer_ptr_ptr_addr, count_ptr_addr, allocator=None):
        if allocator is None:
            return 0x800000000000000C
        print(f"       -> [LocateHandleBuffer] Returning {len(self.partitions_addr)} PartitionEntry handles.")
        handle_array_size = 8 * len(self.partitions_addr)
        allocated_handle_addr = allocator(handle_array_size)
        for i, partition_addr in enumerate(self.partitions_addr):
            mu.mem_write(allocated_handle_addr + i * 8, struct.pack("<Q", HANDLE_INDEX_0 + i))
        mu.mem_write(count_ptr_addr, struct.pack("<Q", len(self.partitions_addr)))
        mu.mem_write(buffer_ptr_ptr_addr, struct.pack("<Q", allocated_handle_addr))
        print(f"       -> [LocateHandleBuffer] Allocated partition handle array at 0x{allocated_handle_addr:X}")
        return 0

    def handle_open_protocol(self, mu, handle, interface_ptr_ptr_addr):
        if handle == DISK_HANDLE:
            partition_addr = self.disk_addr
            #print(f"       -> [OpenProtocol] Returning partition array for disk 0x{handle:X} at 0x{partition_addr:X}.")
        else:
            partition_index = handle - HANDLE_INDEX_0
            partition_addr = self.partitions_addr[partition_index]
            #print(f"       -> [OpenProtocol] Partition handle 0x{handle:X}, returning partition array at 0x{partition_addr:X}")
        
        mu.mem_write(interface_ptr_ptr_addr, struct.pack("<Q", partition_addr))
        return 0

class VerifiedBootProtocol(Protocol):
    def __init__(self):
        super().__init__(defines.EFI_VERIFIED_BOOT_PROTOCOL_GUID)
        self.addr = 0
        self.stubs_addr = 0

    def setup(self, mu):
        self.addr = allocate_mock(128)
        self.stubs_addr = allocate_mock(12 * 10)
        # struct _QCOM_VERIFIEDBOOT_PROTOCOL { UINT64 Revision; (10 func ptrs...) }
        mu.mem_write(self.addr, struct.pack("<Q", 0x0000000000010003)) # Revision
        for i in range(10):
            stub_addr = self.stubs_addr + (i * 12)
            insn1 = (0xD2800000 | (i << 5) | 16) # MOVZ X16, #i
            insn2 = 0xD4200080 # BRK #4
            insn3 = 0xD65F03C0 # RET
            mu.mem_write(stub_addr, struct.pack("<III", insn1, insn2, insn3))
            mu.mem_write(self.addr + 8 + (i * 8), struct.pack("<Q", stub_addr))

    def handle_locate_protocol(self, mu, interface_ptr_ptr_addr):
        print("       -> Found requests for EFI_VERIFIED_BOOT_PROTOCOL, returning specific mock interface.")
        mu.mem_write(interface_ptr_ptr_addr, struct.pack("<Q", self.addr))
        return 0

    def handle_call(self, mu, pc):
        func_idx = mu.reg_read(UC_ARM64_REG_X16)
        vb_funcs = [
            "VBRwDeviceState",
            "VBDeviceInit",
            "VBSendRot",
            "VBSendMilestone",
            "VBVerifyImage",
            "VBDeviceResetState",
            "VBIsDeviceSecure",
            "VBGetBootState",
            "VBGetCertFingerPrint",
            "VBIsKeymasterEnabled"
        ]
        
        func_name = vb_funcs[func_idx] if func_idx < len(vb_funcs) else f"Unknown_VB_Func_{func_idx}"
        
        x0 = mu.reg_read(UC_ARM64_REG_X0)
        x1 = mu.reg_read(UC_ARM64_REG_X1)
        x2 = mu.reg_read(UC_ARM64_REG_X2)
        x3 = mu.reg_read(UC_ARM64_REG_X3)
        x4 = mu.reg_read(UC_ARM64_REG_X4)
        x5 = mu.reg_read(UC_ARM64_REG_X5)
        
        print(f"[UEFI] VerifiedBoot::{func_name} | Args: 0x{x0:X}, 0x{x1:X}, 0x{x2:X}, 0x{x3:X}, 0x{x4:X}, 0x{x5:X}")
        
        ret_status = 0
        # Additional logic for specific functions
        if func_name == "VBRwDeviceState":
            op_type = x1
            buf_ptr = x2
            buf_len = x3
            
            # Enum vb_device_state_op_t: 0=READ_CONFIG, 1=WRITE_CONFIG
            if op_type == 0: # READ_CONFIG
                devinfo_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "devinfo.img")
                if os.path.isfile(devinfo_path):
                    try:
                        with open(devinfo_path, "rb") as f:
                            devinfo_data = f.read(buf_len)
                        
                        # Pad with zeros if file size is less than buf_len
                        if len(devinfo_data) < buf_len:
                            devinfo_data += b"\x00" * (buf_len - len(devinfo_data))
                            
                        mu.mem_write(buf_ptr, devinfo_data)
                        print(f"       -> [VBRwDeviceState] Read {len(devinfo_data)} bytes from devinfo.img into 0x{buf_ptr:X}")
                    except Exception as e:
                        print(f"       -> [VBRwDeviceState] Error reading devinfo.img: {e}")
                        ret_status = 0x800000000000000E # EFI_NOT_FOUND (Or EFI_DEVICE_ERROR)
                else:
                    print(f"       -> [VBRwDeviceState] devinfo.img not found! Returning zeros.")
                    try:
                        mu.mem_write(buf_ptr, b"\x00" * buf_len)
                    except UcError:
                        pass
            elif op_type == 1: # WRITE_CONFIG
                print(f"       -> [VBRwDeviceState] Ignored write to devinfo (len={buf_len})")
        elif func_name == "VBIsDeviceSecure":
            buf_ptr = x1
            mu.mem_write(buf_ptr, struct.pack("<Q", 1))
            ret_status = 0

        # Return Status in X0
        mu.reg_write(UC_ARM64_REG_X0, ret_status)

"""
typedef struct {
  UINT64                         Version;
  InterruptIntf                  *Interrupt;
  TimerIntf                      *Timer;
  ThreadIntf                     *Thread;
  EventIntf                      *Event;
  MutexIntf                      *Mutex;
  SemIntf                        *Sem;
  SpinlockIntf                   *Spinlock;
  MpCpuIntf                      *MpCpu;
  WDogIntf                       *WDog;
  GET_LIB_VERSION                 GetLibVersion; // Major [31:16], Minor {15:0]
  LockIntf                       *Lock;
}EFI_KERNEL_PROTOCOL;
typedef struct {
  REGISTER_INTR_HANDLER    RegisterIntrHandler;
  MASK_INTERRUPT           MaskInterrupt;
  UNMASK_INTERRUPT         UnmaskInterrupt;
  CONFIGURE_INTERRUPT      ConfigureInterrupt;
} InterruptIntf;

"""
class KernelInterfaceProtocol(Protocol):
    def __init__(self):
        super().__init__(defines.QCOM_KERNEL_INTERFACE_PROTOCOL_GUID)

    def setup(self, mu, mock_func_addr):
        self.addr = allocate_mock(12 * 8)

        hook_i = 0
        def create_hooks(num_funcs):
            nonlocal hook_i
            stubs_addr = allocate_mock(num_funcs * 8)
            struct_addr = allocate_mock(num_funcs * 8)
            for i in range(num_funcs):
                stub_addr = stubs_addr + (i * 8)
                mu.mem_write(stub_addr, defines.DYNAMIC_HOOK_STUB)
                register_dynamic_hook(stub_addr, self, hook_i)
                mu.mem_write(struct_addr + (i * 8), struct.pack("<Q", stub_addr))
                hook_i += 1
            return struct_addr
        self.interrupt_stubs_addr = create_hooks(4)
        self.timer_stubs_addr = create_hooks(4)
        self.thread_stubs_addr = create_hooks(24)
        self.event_stubs_addr = create_hooks(8)
        self.mutex_stubs_addr = create_hooks(6)
        self.sem_stubs_addr = create_hooks(6)
        self.spinlock_stubs_addr = create_hooks(5)
        self.mpcpu_stubs_addr = create_hooks(14)
        self.wdog_stubs_addr = create_hooks(6)
        self.getlibversion_stubs_addr = allocate_mock(8 * 1)
        mu.mem_write(self.getlibversion_stubs_addr, defines.DYNAMIC_HOOK_STUB)
        register_dynamic_hook(self.getlibversion_stubs_addr, self, hook_i)
        hook_i += 1
        self.lock_stubs_addr = create_hooks(5)
        # struct _EFI_KERNEL_PROTOCOL { UINT64 Revision; InterruptIntf *Interrupt; TimerIntf *Timer; ThreadIntf *Thread; EventIntf *Event; MutexIntf *Mutex; SemIntf *Sem; SpinlockIntf *Spinlock; MpCpuIntf *MpCpu; WDogIntf *WDog; GET_LIB_VERSION GetLibVersion; LockIntf *Lock }
        mu.mem_write(self.addr, struct.pack("<12Q", 0x0000000000010006,
        self.interrupt_stubs_addr,
        self.timer_stubs_addr,
        self.thread_stubs_addr,
        self.event_stubs_addr,
        self.mutex_stubs_addr,
        self.sem_stubs_addr,
        self.spinlock_stubs_addr,
        self.mpcpu_stubs_addr,
        self.wdog_stubs_addr,
        self.getlibversion_stubs_addr,
        self.lock_stubs_addr))  # Revision
    
    def handle_hook(self, mu, funcidx):
        print(f"       -> [KernelInterfaceProtocol] Hooked function {funcidx}")
        mu.reg_write(UC_ARM64_REG_X0, 0)

        if funcidx == 11: # GetCurrentThread
            mu.reg_write(UC_ARM64_REG_X0, 0)



class MemCardInfoProtocol(Protocol):
    def __init__(self):
        super().__init__(defines.EFI_MEM_CARD_INFO_PROTOCOL_GUID)
        self.addr = 0
        self.stubs_addr = 0

    def setup(self, mu):
        self.addr = allocate_mock(0x40)
        self.stubs_addr = allocate_mock(12 * 3)
        # struct _EFI_MEM_CARD_INFO_PROTOCOL { UINT64 Revision; GetCardInfo; GetBootLU; SetBootLU }
        mu.mem_write(self.addr, struct.pack("<Q", 0x0000000000010003))  # Revision
        for i in range(3):
            stub_addr = self.stubs_addr + (i * 12)
            insn1 = (0xD2800000 | (i << 5) | 16) # MOVZ X16, #i
            insn2 = 0xD42000C0 # BRK #6
            insn3 = 0xD65F03C0 # RET
            mu.mem_write(stub_addr, struct.pack("<III", insn1, insn2, insn3))
            mu.mem_write(self.addr + 8 + (i * 8), struct.pack("<Q", stub_addr))

    def handle_locate_protocol(self, mu, interface_ptr_ptr_addr):
        print("       -> Found requests for EFI_MEM_CARD_INFO_PROTOCOL, returning specific mock interface.")
        mu.mem_write(interface_ptr_ptr_addr, struct.pack("<Q", self.addr))
        return 0

    def handle_locate_handle_buffer(self, mu, buffer_ptr_ptr_addr, count_ptr_addr, allocator=None):
        if allocator is None:
            return 0x800000000000000C
        print("       -> [LocateHandleBuffer] Returning 1 dummy MemCard Info handle.")
        handle_array_size = 8 * 1
        allocated_handle_addr = allocator(handle_array_size)
        mu.mem_write(allocated_handle_addr, struct.pack("<Q", MEMCARD_INFO_HANDLE))
        mu.mem_write(count_ptr_addr, struct.pack("<Q", 1))
        mu.mem_write(buffer_ptr_ptr_addr, struct.pack("<Q", allocated_handle_addr))
        print(f"       -> [LocateHandleBuffer] Allocated handle array at 0x{allocated_handle_addr:X}")
        return 0

    def handle_open_protocol(self, mu, handle, interface_ptr_ptr_addr):
        print("       -> [OpenProtocol] Returning mocked MemCard Info Protocol.")
        mu.mem_write(interface_ptr_ptr_addr, struct.pack("<Q", self.addr))
        return 0

    def handle_call(self, mu, pc):
        func_idx = mu.reg_read(UC_ARM64_REG_X16)
        memcard_funcs = [
            "GetCardInfo",
            "GetBootLU",
            "SetBootLU"
        ]
        
        func_name = memcard_funcs[func_idx] if func_idx < len(memcard_funcs) else f"Unknown_MemCard_Func_{func_idx}"
        
        protocol_addr = mu.reg_read(UC_ARM64_REG_X0)  # This (protocol pointer)
        x1 = mu.reg_read(UC_ARM64_REG_X1)  # First parameter
        x2 = mu.reg_read(UC_ARM64_REG_X2)  # Second parameter
        x3 = mu.reg_read(UC_ARM64_REG_X3)
        x4 = mu.reg_read(UC_ARM64_REG_X4)
        x5 = mu.reg_read(UC_ARM64_REG_X5)
        
        # Determine which partition this is based on protocol address
        # Note: MemCardInfo protocol is single instance, but we can still
        # return device-specific values based on context
        partition_name = "devinfo"  # Default
        mfr_id = 0x1234
        oem_id = 0x5678
        bootlu_value = 1
        
        print(f"[UEFI] MemCardInfo::{func_name} | Args: 0x{protocol_addr:X}, 0x{x1:X}, 0x{x2:X}, 0x{x3:X}, 0x{x4:X}, 0x{x5:X}")
        
        ret_status = 0
        if func_name == "GetCardInfo":
            # X1 = pointer to MEM_CARD_INFO output buffer
            card_info_addr = x1
            try:
                # Build a dummy MEM_CARD_INFO structure
                card_info = bytearray(312)  # 312 bytes for all fields and padding
                
                # mfr_id, oem_id (little-endian UINT16)
                struct.pack_into("<HH", card_info, 0, mfr_id, oem_id)
                
                # product_serial_num[252] - fill with device-specific serial
                serial = b"a" * 252
                card_info[12:12+len(serial)] = serial
                
                # serial_num_len (UINT32) at offset 264
                struct.pack_into("<I", card_info, 264, len(serial))
                
                # rpmb_size_in_byte (UINT32) at offset 300
                struct.pack_into("<I", card_info, 300, 0x10000000)
                
                # reliable_write_count (UINT32) at offset 304
                struct.pack_into("<I", card_info, 304, 0)
                
                # card_type[4] - "UFS\0"
                #card_info[308:312] = b"VBLK"
                card_info[308:312] = b"UFS\0"
                ensure_mapped(mu, card_info_addr, 312)
                mu.mem_write(card_info_addr, bytes(card_info))
                print(f"       -> [GetCardInfo] Returned card info at 0x{card_info_addr:X} (mfr_id: 0x{mfr_id:04X}, partition: {partition_name})")
                ret_status = 0
            except UcError as e:
                print(f"       -> [GetCardInfo] Failed to write card info: {e}")
                ret_status = 0x800000000000000F  # EFI_INVALID_PARAMETER
        
        elif func_name == "GetBootLU":
            # X1 = pointer to UINT32 output (BootLU value)
            bootlu_addr = x1
            try:
                ensure_mapped(mu, bootlu_addr, 4)
                mu.mem_write(bootlu_addr, struct.pack("<I", bootlu_value))
                print(f"       -> [GetBootLU] Returned BootLU={bootlu_value} at 0x{bootlu_addr:X}")
                ret_status = 0
            except UcError as e:
                print(f"       -> [GetBootLU] Failed to write BootLU: {e}")
                ret_status = 0x800000000000000F
        
        elif func_name == "SetBootLU":
            # X1 = BootLU value to set
            new_bootlu = x1
            print(f"       -> [SetBootLU] Setting BootLU to {new_bootlu} (ignored)")
            ret_status = 0
        
        # Return Status in X0
        mu.reg_write(UC_ARM64_REG_X0, ret_status)

class RamPartitionProtocol(Protocol):
    def __init__(self):
        super().__init__(defines.EFI_RAM_PARTITION_PROTOCOL_GUID)
        self.addr = 0
        self.stubs_addr = 0

    def setup(self, mu):
        self.addr = allocate_mock(0x200) # Includes stubs
        self.stubs_addr = self.addr + 0x100
        # struct _EFI_RAMPARTITION_PROTOCOL { UINT64 Revision; ... }
        mu.mem_write(self.addr, struct.pack("<Q", 0x0000000000010002))  # Revision
        for i in range(5):
            stub_addr = self.stubs_addr + (i * 12)
            insn1 = (0xD2800000 | (i << 5) | 16) # MOVZ X16, #i
            insn2 = 0xD4200100 # BRK #7
            insn3 = 0xD65F03C0 # RET
            mu.mem_write(stub_addr, struct.pack("<III", insn1, insn2, insn3))
            mu.mem_write(self.addr + 8 + (i * 8), struct.pack("<Q", stub_addr))

    def handle_locate_protocol(self, mu, interface_ptr_ptr_addr):
        print("       -> Found requests for EFI_RAMPARTITION_PROTOCOL, returning specific mock interface.")
        mu.mem_write(interface_ptr_ptr_addr, struct.pack("<Q", self.addr))
        return 0

    def handle_call(self, mu, pc):
        func_idx = mu.reg_read(UC_ARM64_REG_X16)
        func_names = [
            "GetRamPartitionVersion",
            "GetHighestBankBit",
            "GetRamPartitions",
            "GetMinPasrSize",
            "GetPreLoadedImageTable"
        ]
        func_name = func_names[func_idx] if func_idx < len(func_names) else f"Unknown_{func_idx}"
        x0 = mu.reg_read(UC_ARM64_REG_X0)
        x1 = mu.reg_read(UC_ARM64_REG_X1)
        x2 = mu.reg_read(UC_ARM64_REG_X2)
        x3 = mu.reg_read(UC_ARM64_REG_X3)
        x4 = mu.reg_read(UC_ARM64_REG_X4)
        x5 = mu.reg_read(UC_ARM64_REG_X5)
        print(f"[UEFI] RamPartition::{func_name} | Args: 0x{x0:X}, 0x{x1:X}, 0x{x2:X}, 0x{x3:X}, 0x{x4:X}, 0x{x5:X}")
        ret_status = 0
        if func_name == "GetRamPartitionVersion":
            # x1: MajorVersion, x2: MinorVersion
            try:
                ensure_mapped(mu, x1, 4)
                ensure_mapped(mu, x2, 4)
                mu.mem_write(x1, struct.pack("<I", 1))
                mu.mem_write(x2, struct.pack("<I", 2))
            except UcError:
                ret_status = 0x800000000000000F
        elif func_name == "GetHighestBankBit":
            try:
                ensure_mapped(mu, x1, 4)
                mu.mem_write(x1, struct.pack("<I", 47))
            except UcError:
                ret_status = 0x800000000000000F
        elif func_name == "GetRamPartitions":
            # x1 = RamPartitions pointer, x2 = NumPartition pointer
            try:
                ensure_mapped(mu, x2, 4)
                if x1 == 0:
                    # First call: just return the count needed
                    mu.mem_write(x2, struct.pack("<I", 3))
                    ret_status = 0x8000000000000005  # EFI_BUFFER_TOO_SMALL
                    print(f"       -> [GetRamPartitions] First call (buffer=NULL): returning NumPartitions=2, Status=EFI_BUFFER_TOO_SMALL")
                else:
                    # Second call: fill the partition entries
                    ensure_mapped(mu, x1, 16 * 3)
                    # Partition 1: Base=0x8000_0000, AvailableLength=0x200_0000 (32 MB)
                    mu.mem_write(x1, struct.pack("<QQ", 0x80000000, 0x2000000))
                    # Partition 2: Base=0x8200_0000, AvailableLength=0x400_0000 (64 MB)
                    mu.mem_write(x1 + 16, struct.pack("<QQ", 0x82000000, 0x4000000))
                    # Partition 3: Base=0x9400_0000, AvailableLength=0x1_0000_0000 (4 GB)
                    mu.mem_write(x1 + 32, struct.pack("<QQ", 0x84000000, 0x8000000))
                    mu.mem_write(x2, struct.pack("<I", 3))
                    ret_status = 0
                    print(f"       -> [GetRamPartitions] Second call: filled buffer at 0x{x1:X} with 2 partitions")
            except UcError:
                ret_status = 0x800000000000000F
        elif func_name == "GetMinPasrSize":
            try:
                ensure_mapped(mu, x1, 4)
                mu.mem_write(x1, struct.pack("<I", 0x100000))
            except UcError:
                ret_status = 0x800000000000000F
        elif func_name == "GetPreLoadedImageTable":
            try:
                ensure_mapped(mu, x2, 4)
                mu.mem_write(x2, struct.pack("<I", 0))
            except UcError:
                ret_status = 0x800000000000000F
        mu.reg_write(UC_ARM64_REG_X0, ret_status)

class UsbDeviceProtocol(Protocol):

    UsbDeviceEventNoEvent = 0
    UsbDeviceEventDeviceStateChange = 1
    UsbDeviceEventTransferNotification = 2
    UsbDeviceEventOemEvent = 3

    UsbDeviceStateConnected = 0
    UsbDeviceStateDisconnected = 1

    UsbDeviceTransferStatusActive = 0
    UsbDeviceTransferStatusCompleteOK = 1
    UsbDeviceTransferStatusCancelled = 2
    UsbDeviceTransferStatusCompleteError = 3

    USB_ENDPOINT_DIRECTION_OUT = 0
    USB_ENDPOINT_DIRECTION_IN = 1

    def __init__(self):
        super().__init__(defines.EFI_USB_DEVICE_PROTOCOL_GUID)
        self.addr = 0
        self.stubs_addr = 0
        self.malloc_ptr = 0xa0000000  # Start of EfiConventionalMemory region
        self.malloc_map = {}  # Track USB buffer allocations
        self.event_queue = queue.Queue()
        self.usb_event_state = 0
        self.no_event_counter = 0

    def setup(self, mu):
        self.addr = allocate_mock(0x80)
        self.stubs_addr = allocate_mock(12 * 10)
        # struct _EFI_USB_DEVICE_PROTOCOL { UINTN Revision; ... }
        mu.mem_write(self.addr, struct.pack("<Q", 0x0000000000010001))  # Revision
        for i in range(9):
            stub_addr = self.stubs_addr + (i * 12)
            insn1 = (0xD2800000 | (i << 5) | 16) # MOVZ X16, #i
            insn2 = 0xD4200120 # BRK #8
            insn3 = 0xD65F03C0 # RET
            mu.mem_write(stub_addr, struct.pack("<III", insn1, insn2, insn3))
            mu.mem_write(self.addr + 8 + (i * 8), struct.pack("<Q", stub_addr))
        
        mu.mem_map(self.malloc_ptr, 0x10000000)

    def handle_locate_protocol(self, mu, interface_ptr_ptr_addr):
        print("       -> Found requests for EFI_USB_DEVICE_PROTOCOL, returning specific mock interface.")
        mu.mem_write(interface_ptr_ptr_addr, struct.pack("<Q", self.addr))
        return 0

    def handle_call(self, mu, pc):
        func_idx = mu.reg_read(UC_ARM64_REG_X16)
        usb_func_names = [
            "Start",
            "Send",
            "HandleEvent",
            "AllocateTransferBuffer",
            "FreeTransferBuffer",
            "Stop",
            "AbortXfer",
            "SetEndpointStallState",
            "StartEx"
        ]
        func_name = usb_func_names[func_idx] if func_idx < len(usb_func_names) else f"Unknown_{func_idx}"
        
        x0 = mu.reg_read(UC_ARM64_REG_X0)
        x1 = mu.reg_read(UC_ARM64_REG_X1)
        x2 = mu.reg_read(UC_ARM64_REG_X2)
        x3 = mu.reg_read(UC_ARM64_REG_X3)
        x4 = mu.reg_read(UC_ARM64_REG_X4)
        x5 = mu.reg_read(UC_ARM64_REG_X5)
        
        print(f"[UEFI] UsbDevice::{func_name} | Args: 0x{x0:X}, 0x{x1:X}, 0x{x2:X}, 0x{x3:X}, 0x{x4:X}, 0x{x5:X}")
        
        ret_status = 0
        
        if func_name == "Start":
            print(f"       -> [UsbDevice::Start] Starting USB device with descriptors")
            ret_status = 0
        
        elif func_name == "Send":
            endpoint = x0
            size = x1
            buf_ptr = x2

            direction = (endpoint & 0x80) >> 7
            if direction == 0:
                # Recv
                print(f"       -> [UsbDevice::Send] Recv {size} bytes on endpoint {endpoint} from 0x{buf_ptr:X}")
                if self.usb_event_state == 1:
                    if len(fastboot_cmds) > 0:
                        data = fastboot_cmds.pop(0).encode()
                        write_size = len(data)
                        if size >= write_size:
                            mu.mem_write(buf_ptr, data)
                            # Recv completion event
                            self.usb_event_state = 1
                            # OUT: Host to device
                            ep = 1 | (self.USB_ENDPOINT_DIRECTION_OUT << 7)

                            self.event_queue.put((self.UsbDeviceEventTransferNotification, struct.pack("<IBxxxQQ", self.UsbDeviceTransferStatusCompleteOK, ep, write_size, buf_ptr)))
                        else:
                            print(f"       -> [UsbDevice::Send] Size {size} is smaller than data size {write_size}")

            else:
                # Send
                print(f"       -> [UsbDevice::Send] Send {size} bytes on endpoint {endpoint} from 0x{buf_ptr:X}")
                data = mu.mem_read(buf_ptr, size)
                print(f"       -> [UsbDevice::Send] Data: {data.decode('utf-8', errors='ignore')}")

                # Send completion event
                # IN: Device to host
                ep = 1 | (self.USB_ENDPOINT_DIRECTION_IN << 7)

                self.event_queue.put((self.UsbDeviceEventTransferNotification, struct.pack("<IBxxxQQ", self.UsbDeviceTransferStatusCompleteOK, ep, size, 0)))

            ret_status = 0
        
        elif func_name == "HandleEvent":
            """
/** USB Device Event */
typedef enum {
  UsbDeviceEventNoEvent,
  UsbDeviceEventDeviceStateChange,
  UsbDeviceEventTransferNotification,
  UsbDeviceEventOemEvent
} USB_DEVICE_EVENT;
/** USB Device State */
typedef enum {
  UsbDeviceStateConnected,
  UsbDeviceStateDisconnected
} USB_DEVICE_STATE;
/** Data associated with the USB DEVICE Event. */
typedef union {
  USB_DEVICE_STATE DeviceState;
  USB_DEVICE_TRANSFER_OUTCOME TransferOutcome;
  USB_DEVICE_OEM_DATA OemData;
} USB_DEVICE_EVENT_DATA;


/** USB Device Transfer Status */
typedef enum {
  UsbDeviceTransferStatusActive,
  UsbDeviceTransferStatusCompleteOK,
  UsbDeviceTransferStatusCancelled,
  UsbDeviceTransferStatusCompleteError,
} USB_DEVICE_TRANSFER_STATUS;
/** USB TRANSFER OUTCOME */
typedef struct {
  USB_DEVICE_TRANSFER_STATUS Status;
  UINT8 EndpointIndex;
  UINTN BytesCompleted;
  VOID *DataBuffer;
} USB_DEVICE_TRANSFER_OUTCOME;
            """
            event_ptr = x0
            datasize_ptr = x1
            event_data_ptr = x2
            if self.usb_event_state == 0:
                self.usb_event_state = 1
                self.event_queue.put((1, struct.pack("<I", 0)))
            try:
                ensure_mapped(mu, event_ptr, 4)
                ensure_mapped(mu, datasize_ptr, 8)
                ensure_mapped(mu, event_data_ptr, 4)

                if not self.event_queue.empty():
                    event_type, event_data = self.event_queue.get()
                    mu.mem_write(event_ptr, struct.pack("<I", event_type))
                    mu.mem_write(datasize_ptr, struct.pack("<Q", len(event_data)))  # Event data size
                    mu.mem_write(event_data_ptr, event_data)
                    print(f"       -> [UsbDevice::HandleEvent] Returning event type {event_type}")
                    ret_status = 0
                else:
                    mu.mem_write(event_ptr, struct.pack("<I", 0))  # UsbDeviceEventNoEvent
                    mu.mem_write(datasize_ptr, struct.pack("<Q", 0))  # No event data
                    print(f"       -> [UsbDevice::HandleEvent] Returning no event")
                    ret_status = 0
                    self.no_event_counter += 1
                    if self.no_event_counter > 10:
                        # Stop the emulation
                        print("       -> [UsbDevice::HandleEvent] No events for 10 consecutive calls, stopping emulation.")
                        mu.emu_stop()
            except UcError as e:
                print(f"       -> [UsbDevice::HandleEvent] Error: {e}")
                ret_status = 0x800000000000000F
        
        elif func_name == "AllocateTransferBuffer":
            size = x0
            buffer_ptr_addr = x1
            allocated_addr = align_up(self.malloc_ptr, 16)
            self.malloc_ptr = allocated_addr + align_up(size, 16)
            print(f"       -> [AllocateTransferBuffer] Args: size=0x{size:X}, buffer_ptr_addr=0x{buffer_ptr_addr:X}")
            if self.malloc_ptr > 0x90000000 + (0x10000000 * 0x1000):
                print(f"       -> [AllocateTransferBuffer] Out of conventional memory!")
                ret_status = 0x800000000000000C  # EFI_OUT_OF_RESOURCES
            else:
                self.malloc_map[allocated_addr] = size
                try:
                    ensure_mapped(mu, buffer_ptr_addr, 8)
                    mu.mem_write(buffer_ptr_addr, struct.pack("<Q", allocated_addr))
                    print(f"       -> [AllocateTransferBuffer] Allocated 0x{size:X} bytes at 0x{allocated_addr:X}")
                    ret_status = 0
                except UcError as e:
                    print(f"       -> [AllocateTransferBuffer] Failed to write buffer pointer: {e}")
                    ret_status = 0x800000000000000C
        
        elif func_name == "FreeTransferBuffer":
            buffer_addr = x0
            if buffer_addr in self.malloc_map:
                size = self.malloc_map[buffer_addr]
                del self.malloc_map[buffer_addr]
                print(f"       -> [FreeTransferBuffer] Freed 0x{size:X} bytes at 0x{buffer_addr:X}")
                ret_status = 0
            else:
                print(f"       -> [FreeTransferBuffer] Invalid pointer 0x{buffer_addr:X}")
                ret_status = 0x800000000000000F
        
        elif func_name == "Stop":
            print(f"       -> [UsbDevice::Stop] Stopping USB device")
            ret_status = 0
        
        elif func_name == "AbortXfer":
            endpoint = x0
            print(f"       -> [UsbDevice::AbortXfer] Aborting transfer on endpoint {endpoint}")
            ret_status = 0
        
        elif func_name == "SetEndpointStallState":
            endpoint = x0
            state = x1
            print(f"       -> [UsbDevice::SetEndpointStallState] Endpoint {endpoint} stall state = {state}")
            ret_status = 0
        
        elif func_name == "StartEx":
            desc_set_ptr = x0
            print(f"       -> [UsbDevice::StartEx] Starting USB device with descriptor set at 0x{desc_set_ptr:X}")
            ret_status = 0
        
        mu.reg_write(UC_ARM64_REG_X0, ret_status)

class StatusCodeProtocol(Protocol):
    def __init__(self):
        super().__init__(defines.EFI_STATUS_CODE_PROTOCOL_GUID)
        self.report_status_code_addr = 0

    def setup(self, mu, mock_region_addr):
        self.addr = allocate_mock(0x10) # Enough for ReportStatusCode pointer
        self.report_status_code_addr = mock_region_addr + 0x3000
        # BRK #3 (0xD4200060), RET (0xD65F03C0)
        mu.mem_write(self.report_status_code_addr, struct.pack("<II", 0xD4200060, 0xD65F03C0))
        # Head of the protocol points to the stub
        mu.mem_write(self.addr, struct.pack("<Q", self.report_status_code_addr))

    def handle_locate_protocol(self, mu, interface_ptr_ptr_addr):
        print("       -> [LocateProtocol] StatusCodeProtocol found, returning interface.")
        mu.mem_write(interface_ptr_ptr_addr, struct.pack("<Q", self.addr))
        return 0

    """
    typedef struct {
      ///
      /// The size of the structure. This is specified to enable future expansion.
      ///
      UINT16    HeaderSize;
      ///
      /// The size of the data in bytes. This does not include the size of the header structure.
      ///
      UINT16    Size;
      ///
      /// The GUID defining the type of the data.
      ///
      EFI_GUID  Type;
    } EFI_STATUS_CODE_DATA;
    // EFI_GUID's alignment is 4 bytes. So this struct has no padding.
    """
    def handle_call(self, mu, pc):
        # EFI_REPORT_STATUS_CODE args: X0=Type, X1=Value, X2=Instance, X3=CallerId, X4=Data
        # Data is EFI_STATUS_CODE_DATA
        type_val = mu.reg_read(UC_ARM64_REG_X0)
        val      = mu.reg_read(UC_ARM64_REG_X1)
        inst     = mu.reg_read(UC_ARM64_REG_X2)
        caller   = mu.reg_read(UC_ARM64_REG_X3)
        data     = mu.reg_read(UC_ARM64_REG_X4)

        header_size, size = struct.unpack("<HH", mu.mem_read(data, 4))
        guid = mu.mem_read(data + 4, 16)
        tail = mu.mem_read(data + 4 + 16, size)
        error_level = struct.unpack("<I", tail[0:4])[0]
        args = struct.unpack("<12Q", tail[4:4+12*8])
        format_string = tail[4+12*8:]
        
        #print(f"[UEFI] ReportStatusCode | Type: 0x{type_val:X}, Value: 0x{val:X}, Inst: 0x{inst:X}, CallerId: 0x{caller:X}, Data: 0x{data:X}, Size: 0x{size:X}, GUID: {guid_to_str(guid)}")
        #hexdump(tail)

        s = process_format_string(mu, format_string.split(b'\x00')[0].decode('utf-8', errors='ignore'), args)
        print(f"[ReportStatusCode] {s}")
        
        # Check for EFI_ERROR_UNRECOVERED (EFI_STATUS_CODE_TYPE with highest nibble = 9)
        if (type_val & 0xF0000000) == 0x90000000:
            print("\n[CRITICAL] EFI_ERROR_UNRECOVERED received! Halting emulation.")
            # dump_stack_trace(mu) # This function is in emu.py, might not be accessible here easily
            mu.emu_stop()
            return

        # Return EFI_SUCCESS in X0
        mu.reg_write(UC_ARM64_REG_X0, 0)
        # Advance PC past BRK instruction to the RET instruction
        mu.reg_write(UC_ARM64_REG_PC, pc + 4)

class GraphicsOutputProtocol(Protocol):
    def __init__(self):
        super().__init__(defines.EFI_GRAPHICS_OUTPUT_PROTOCOL_GUID)
        self.addr = 0
        self.mode_addr = 0
        self.info_addr = 0
        self.stubs_addr = 0

    def setup(self, mu):
        # Allocate memory for the protocol and its structures
        self.addr = allocate_mock(0x100)
        self.mode_addr = allocate_mock(0x100)
        self.info_addr = allocate_mock(0x100)
        self.stubs_addr = allocate_mock(0x40)

        # 1. Setup stubs for QueryMode, SetMode, Blt
        # BRK #9 (0xD4200140), RET (0xD65F03C0)
        for i in range(3):
            stub_addr = self.stubs_addr + (i * 12)
            insn1 = (0xD2800000 | (i << 5) | 16) # MOVZ X16, #i
            insn2 = 0xD4200140 # BRK #9
            insn3 = 0xD65F03C0 # RET
            mu.mem_write(stub_addr, struct.pack("<III", insn1, insn2, insn3))
            # Write stub addresses to the protocol table (QueryMode, SetMode, Blt)
            mu.mem_write(self.addr + (i * 8), struct.pack("<Q", stub_addr))

        # 2. Setup EFI_GRAPHICS_OUTPUT_PROTOCOL_MODE
        # MaxMode, Mode, Info*, SizeOfInfo, FrameBufferBase, FrameBufferSize
        mu.mem_write(self.mode_addr, struct.pack("<IIQQQQ", 1, 0, self.info_addr, 36, 0x100000000, 1024*768*4))
        # Write Mode pointer to the protocol table (at offset 24)
        mu.mem_write(self.addr + 24, struct.pack("<Q", self.mode_addr))

        # 3. Setup EFI_GRAPHICS_OUTPUT_MODE_INFORMATION
        # Version, Horizontal, Vertical, PixelFormat, PixelInformation, PixelsPerScanLine
        mu.mem_write(self.info_addr, struct.pack("<IIII", 0, 1024, 768, 1)) # PixelBlueGreenRedReserved8BitPerColor
        mu.mem_write(self.info_addr + 16, b"\x00" * 16) # PixelInformation (dummy mask)
        mu.mem_write(self.info_addr + 32, struct.pack("<I", 1024)) # PixelsPerScanLine

        print(f"[INIT] GraphicsOutputProtocol at 0x{self.addr:X}, Mode at 0x{self.mode_addr:X}, Info at 0x{self.info_addr:X}")

    def handle_locate_protocol(self, mu, interface_ptr_ptr_addr):
        print("       -> Found requests for EFI_GRAPHICS_OUTPUT_PROTOCOL, returning mock interface.")
        mu.mem_write(interface_ptr_ptr_addr, struct.pack("<Q", self.addr))
        return 0

    def handle_open_protocol(self, mu, handle, interface_ptr_ptr_addr):
        if handle == 0xDE000020:
            print("       -> [OpenProtocol] Returning mocked Graphics Output Protocol for ConsoleOutHandle.")
        else:
            print("       -> [OpenProtocol] Returning mocked Graphics Output Protocol.")
        mu.mem_write(interface_ptr_ptr_addr, struct.pack("<Q", self.addr))
        return 0

    def handle_call(self, mu, pc):
        func_idx = mu.reg_read(UC_ARM64_REG_X16)
        gop_funcs = ["QueryMode", "SetMode", "Blt"]
        func_name = gop_funcs[func_idx] if func_idx < len(gop_funcs) else f"Unknown_GOP_Func_{func_idx}"
        
        print(f"[UEFI] GraphicsOutput::{func_name} called")
        
        # Default success return
        mu.reg_write(UC_ARM64_REG_X0, 0)

class SimpleTextInputProtocol(Protocol):
    def __init__(self):
        super().__init__(defines.EFI_SIMPLE_TEXT_INPUT_PROTOCOL_GUID)
        self.addr = 0
        self.stubs_addr = 0

    def setup(self, mu):
        self.addr = allocate_mock(0x40)
        self.stubs_addr = allocate_mock(12 * 2)

        # 1. Setup stubs for Reset, ReadKeyStroke
        # BRK #10 (0xD4200160), RET (0xD65F03C0)
        for i in range(2):
            stub_addr = self.stubs_addr + (i * 12)
            insn1 = (0xD2800000 | (i << 5) | 16) # MOVZ X16, #i
            insn2 = 0xD4200160 # BRK #10
            insn3 = 0xD65F03C0 # RET
            mu.mem_write(stub_addr, struct.pack("<III", insn1, insn2, insn3))
            # Write stub addresses to the protocol table (Reset, ReadKeyStroke)
            mu.mem_write(self.addr + (i * 8), struct.pack("<Q", stub_addr))
        
        # 2. WaitForKey event (dummy pointer)
        mu.mem_write(self.addr + 16, struct.pack("<Q", 0xDEADEAD0))

        print(f"[INIT] SimpleTextInputProtocol at 0x{self.addr:X}")

    def handle_locate_protocol(self, mu, interface_ptr_ptr_addr):
        print("       -> Found requests for EFI_SIMPLE_TEXT_INPUT_PROTOCOL, returning mock interface.")
        mu.mem_write(interface_ptr_ptr_addr, struct.pack("<Q", self.addr))
        return 0

    def handle_open_protocol(self, mu, handle, interface_ptr_ptr_addr):
        if handle == 0xDE000010:
            print("       -> [OpenProtocol] Returning mocked Simple Text Input Protocol for ConsoleInHandle.")
        else:
            print("       -> [OpenProtocol] Returning mocked Simple Text Input Protocol.")
        mu.mem_write(interface_ptr_ptr_addr, struct.pack("<Q", self.addr))
        return 0

    def handle_call(self, mu, pc):
        func_idx = mu.reg_read(UC_ARM64_REG_X16)
        input_funcs = ["Reset", "ReadKeyStroke"]
        func_name = input_funcs[func_idx] if func_idx < len(input_funcs) else f"Unknown_Input_Func_{func_idx}"
        
        # print(f"[UEFI] SimpleTextInput::{func_name} called")
        
        if func_name == "ReadKeyStroke":
            # Return EFI_NOT_READY (no key pressed)
            mu.reg_write(UC_ARM64_REG_X0, 0x8000000000000006)
        else:
            mu.reg_write(UC_ARM64_REG_X0, 0)

class SimpleTextOutputProtocol(Protocol):
    def __init__(self):
        super().__init__(defines.EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL_GUID)
        self.addr = 0
        self.mode_addr = 0
        self.stubs_addr = 0

    def setup(self, mu):
        self.addr = allocate_mock(0x80)
        self.mode_addr = allocate_mock(0x40)
        self.stubs_addr = allocate_mock(12 * 10)

        # 1. Setup stubs for Reset, OutputString, TestString, QueryMode, SetMode, SetAttribute, ClearScreen, SetCursorPosition, EnableCursor
        # BRK #11 (0xD4200180), RET (0xD65F03C0)
        for i in range(9):
            stub_addr = self.stubs_addr + (i * 12)
            insn1 = (0xD2800000 | (i << 5) | 16) # MOVZ X16, #i
            insn2 = 0xD4200180 # BRK #11
            insn3 = 0xD65F03C0 # RET
            mu.mem_write(stub_addr, struct.pack("<III", insn1, insn2, insn3))
            # Write stub addresses to the protocol table (0..8)
            mu.mem_write(self.addr + (i * 8), struct.pack("<Q", stub_addr))
        
        # 2. Setup MODE
        # MaxMode, Mode, Attribute, CursorColumn, CursorRow, CursorVisible
        mu.mem_write(self.mode_addr, struct.pack("<IIIIIB", 1, 0, 0x0F, 0, 0, 1))
        mu.mem_write(self.addr + 72, struct.pack("<Q", self.mode_addr))

        print(f"[INIT] SimpleTextOutputProtocol at 0x{self.addr:X}, Mode at 0x{self.mode_addr:X}")

    def handle_locate_protocol(self, mu, interface_ptr_ptr_addr):
        print("       -> Found requests for EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL, returning mock interface.")
        mu.mem_write(interface_ptr_ptr_addr, struct.pack("<Q", self.addr))
        return 0

    def handle_open_protocol(self, mu, handle, interface_ptr_ptr_addr):
        if handle == 0xDE000020:
            print("       -> [OpenProtocol] Returning mocked Simple Text Output Protocol for ConsoleOutHandle.")
        else:
            print("       -> [OpenProtocol] Returning mocked Simple Text Output Protocol.")
        mu.mem_write(interface_ptr_ptr_addr, struct.pack("<Q", self.addr))
        return 0

    def handle_call(self, mu, pc):
        func_idx = mu.reg_read(UC_ARM64_REG_X16)
        output_funcs = ["Reset", "OutputString", "TestString", "QueryMode", "SetMode", "SetAttribute", "ClearScreen", "SetCursorPosition", "EnableCursor"]
        func_name = output_funcs[func_idx] if func_idx < len(output_funcs) else f"Unknown_Output_Func_{func_idx}"
        
        print(f"[UEFI] SimpleTextOutput::{func_name} called")
        
        if func_name == "OutputString":
            # X1 = pointer to NULL-terminated CHAR16 string
            ptr = mu.reg_read(UC_ARM64_REG_X1)
            try:
                s_bytes = bytearray()
                for i in range(0, 512, 2):
                    c1, c2 = struct.unpack("BB", mu.mem_read(ptr+i, 2))
                    if c1 == 0 and c2 == 0: break
                    if c2 == 0: s_bytes.append(c1)
                    else: s_bytes.append(ord('?'))
                print(f"[UEFI_CONOUT] {s_bytes.decode('ascii', errors='ignore')}")
            except:
                pass
        
        mu.reg_write(UC_ARM64_REG_X0, 0)

class HiiFontProtocol(Protocol):
    def __init__(self):
        super().__init__(defines.EFI_HII_FONT_PROTOCOL_GUID)
        self.addr = 0
        self.stubs_addr = 0
        self.allocator = None

    def setup(self, mu, allocator=None):
        self.allocator = allocator
        self.addr = allocate_mock(0x100) # Plenty of space for protocol table
        # Allocate stubs in a separate 16-byte aligned block, far enough
        self.stubs_addr = allocate_mock(0x100) 

        # 1. Setup stubs for StringToImage, StringIdToImage, GetGlyph, GetFontInfo
        # BRK #12 (0xD42001A0), RET (0xD65F03C0)
        for i in range(4):
            stub_addr = self.stubs_addr + (i * 12)
            insn1 = (0xD2800000 | (i << 5) | 16) # MOVZ X16, #i
            insn2 = 0xD42001A0 # BRK #12
            insn3 = 0xD65F03C0 # RET
            mu.mem_write(stub_addr, struct.pack("<III", insn1, insn2, insn3))
            # Write stub addresses to the protocol table (0..3)
            mu.mem_write(self.addr + (i * 8), struct.pack("<Q", stub_addr))

        print(f"[INIT] HiiFontProtocol at 0x{self.addr:X}")

    def handle_locate_protocol(self, mu, interface_ptr_ptr_addr):
        print("       -> Found requests for EFI_HII_FONT_PROTOCOL, returning mock interface.")
        mu.mem_write(interface_ptr_ptr_addr, struct.pack("<Q", self.addr))
        return 0

    def handle_open_protocol(self, mu, handle, interface_ptr_ptr_addr):
        print("       -> [OpenProtocol] Returning mocked Hii Font Protocol.")
        mu.mem_write(interface_ptr_ptr_addr, struct.pack("<Q", self.addr))
        return 0

    def handle_call(self, mu, pc):
        func_idx = mu.reg_read(UC_ARM64_REG_X16)
        font_funcs = ["StringToImage", "StringIdToImage", "GetGlyph", "GetFontInfo"]
        func_name = font_funcs[func_idx] if func_idx < len(font_funcs) else f"Unknown_Font_Func_{func_idx}"
        
        print(f"[UEFI] HiiFont::{func_name} called")
        
        if func_name == "GetGlyph":
            # X1=Char, X2=FontDisplayInfo, X3=Blt**, X4=Baseline*
            blt_ptr_addr = mu.reg_read(UC_ARM64_REG_X3)
            baseline_ptr_addr = mu.reg_read(UC_ARM64_REG_X4)
            
            # Allocate EFI_IMAGE_OUTPUT from heap if available, as guest might free it
            if self.allocator:
                blt_addr = self.allocator(0x20)
            else:
                blt_addr = allocate_mock(0x20)
            
            # Width=8, Height=19 (standard EFI font size or similar used in ABL)
            mu.mem_write(blt_addr, struct.pack("<HH", 8, 19))
            # Image.Bitmap = (dummy pointer)
            mu.mem_write(blt_addr + 8, struct.pack("<Q", 0xDEADEAD1))
            
            mu.mem_write(blt_ptr_addr, struct.pack("<Q", blt_addr))
            if baseline_ptr_addr != 0:
                mu.mem_write(baseline_ptr_addr, struct.pack("<Q", 0)) # Baseline = 0
            
            print("       -> [GetGlyph] Returning dummy 8x19 image.")
            mu.reg_write(UC_ARM64_REG_X0, 0)
        
        elif func_name == "StringToImage":
            # X0=This, X1=Flags, X2=String, X3=StringInfo, X4=Blt**, X5=BltX, X6=BltY, X7=RowInfo**
            # Stack+0: RowInfoSize*
            # Stack+8: StringInfoOut**
            str_ptr = mu.reg_read(UC_ARM64_REG_X2)
            try:
                s_bytes = bytearray()
                for i in range(0, 512, 2):
                    c1, c2 = struct.unpack("BB", mu.mem_read(str_ptr+i, 2))
                    if c1 == 0 and c2 == 0: break
                    if c2 == 0: s_bytes.append(c1)
                    else: s_bytes.append(ord('?'))
                s_val = s_bytes.decode('ascii', errors='ignore')
                print(f"       -> [StringToImage] String: '{s_val}'")
            except:
                pass

            # For HII_DIRECT_TO_SCREEN, it just works.
            # We need to fill RowInfo if requested.
            row_info_ptr_ptr = mu.reg_read(UC_ARM64_REG_X7)
            
            # Read Arg 9 (RowInfoSize*) from stack
            sp = mu.reg_read(UC_ARM64_REG_SP)
            row_info_size_ptr = struct.unpack("<Q", mu.mem_read(sp, 8))[0]
            
            if row_info_ptr_ptr != 0 and row_info_size_ptr != 0:
                # Allocate 1 EFI_HII_ROW_INFO
                # EFI_HII_ROW_INFO: StartIndex(Q), EndIndex(Q), LineHeight(Q), LineWidth(Q), BaselineOffset(Q) = 40 bytes
                if self.allocator:
                    row_info_addr = self.allocator(0x40)
                else:
                    row_info_addr = allocate_mock(0x40)
                # Fill with some reasonable values
                mu.mem_write(row_info_addr, struct.pack("<QQQQQ", 0, len(s_bytes)//2 if 's_bytes' in locals() else 10, 19, 80, 0))
                
                mu.mem_write(row_info_ptr_ptr, struct.pack("<Q", row_info_addr))
                mu.mem_write(row_info_size_ptr, struct.pack("<Q", 1))
            
            print("       -> [StringToImage] returning SUCCESS")
            mu.reg_write(UC_ARM64_REG_X0, 0)
        
        else:
            mu.reg_write(UC_ARM64_REG_X0, 0)

class Hash2Protocol(Protocol):
    def __init__(self):
        super().__init__(defines.EFI_HASH2_PROTOCOL_GUID)
        self.addr = 0
        self.stubs_addr = 0
        self.allocator = None
        self.funcs = ["GetHashSize", "Hash", "HashInit", "HashUpdate", "HashFinal"]
        self.hash_instance = hashlib.sha256()
        self.hashed_size = 0

    def setup(self, mu, allocator=None):
        self.allocator = allocator
        self.addr = allocate_mock(0x100) # Plenty of space for protocol table
        # Allocate stubs in a separate 16-byte aligned block, far enough
        self.stubs_addr = allocate_mock(0x100) 

        # 1. Setup stubs for StringToImage, StringIdToImage, GetGlyph, GetFontInfo
        # BRK #13 (0xD42001C0), RET (0xD65F03C0)
        for i in range(len(self.funcs)):
            stub_addr = self.stubs_addr + (i * 12)
            insn1 = (0xD2800000 | (i << 5) | 16) # MOVZ X16, #i
            insn2 = 0xD42001C0 # BRK #13
            insn3 = 0xD65F03C0 # RET
            mu.mem_write(stub_addr, struct.pack("<III", insn1, insn2, insn3))
            # Write stub addresses to the protocol table (0..3)
            mu.mem_write(self.addr + (i * 8), struct.pack("<Q", stub_addr))

        print(f"[INIT] Hash2Protocol at 0x{self.addr:X}")

    def handle_locate_protocol(self, mu, interface_ptr_ptr_addr):
        print("       -> Found requests for EFI_HASH2_PROTOCOL, returning mock interface.")
        mu.mem_write(interface_ptr_ptr_addr, struct.pack("<Q", self.addr))
        return 0

    def handle_call(self, mu, func_name):
        func_idx = mu.reg_read(UC_ARM64_REG_X16)
        func_name = self.funcs[func_idx] if func_idx < len(self.funcs) else f"Unknown_Hash_Func_{func_idx}"
        
        if func_name == "GetHashSize":
            hash_algo_guid_ptr = mu.reg_read(UC_ARM64_REG_X1)
            hash_size_ptr = mu.reg_read(UC_ARM64_REG_X2)
            print(f"       -> [Hash2] GetHashSize called")
            mu.mem_write(hash_size_ptr, struct.pack("<Q", 0x20))
            mu.reg_write(UC_ARM64_REG_X0, 0)
        elif func_name == "Hash":
            print(f"       -> [Hash2] Hash called")
            mu.reg_write(UC_ARM64_REG_X0, 0)
        elif func_name == "HashInit":
            print(f"       -> [Hash2] HashInit called")
            self.hash_instance = hashlib.sha256()
            self.hashed_size = 0
            mu.reg_write(UC_ARM64_REG_X0, 0)
        elif func_name == "HashUpdate":
            data_ptr = mu.reg_read(UC_ARM64_REG_X1)
            data_size = mu.reg_read(UC_ARM64_REG_X2)
            self.hash_instance.update(mu.mem_read(data_ptr, data_size))
            self.hashed_size += data_size
            mu.reg_write(UC_ARM64_REG_X0, 0)
        elif func_name == "HashFinal":
            data_ptr = mu.reg_read(UC_ARM64_REG_X1)
            mu.mem_write(data_ptr, self.hash_instance.digest())
            print(f"       -> [Hash2] HashFinal called, hashed {self.hashed_size} bytes. Hash: {self.hash_instance.hexdigest()}")
            mu.reg_write(UC_ARM64_REG_X0, 0)
        else:
            mu.reg_write(UC_ARM64_REG_X0, 0)

class QSEEComProtocol(Protocol):
    def __init__(self):
        super().__init__(defines.EFI_QSEECOM_PROTOCOL_GUID)
        self.addr = 0
        self.stub_addr = 0
        self.funcs_offset = 8
        self.funcs = ["QseecomStartApp", "QseecomShutdownApp", "QseecomSendCmd", "QseecomStartAppByGuid"]

    KEYMASTER_UTILS_CMD_ID = 0x200
    KEYMASTER_GET_VERSION = KEYMASTER_UTILS_CMD_ID + 0
    KEYMASTER_SET_ROT = KEYMASTER_UTILS_CMD_ID + 1
    KEYMASTER_READ_KM_DEVICE_STATE = KEYMASTER_UTILS_CMD_ID + 2
    KEYMASTER_WRITE_KM_DEVICE_STATE = KEYMASTER_UTILS_CMD_ID + 3
    KEYMASTER_MILESTONE_CALL = KEYMASTER_UTILS_CMD_ID + 4
    KEYMASTER_GET_AUTH_TOKEN_KEY = KEYMASTER_UTILS_CMD_ID + 5
    KEYMASTER_SECURE_WRITE_PROTECT = KEYMASTER_UTILS_CMD_ID + 6
    KEYMASTER_SET_VERSION = KEYMASTER_UTILS_CMD_ID + 7
    KEYMASTER_SET_BOOT_STATE = KEYMASTER_UTILS_CMD_ID + 8
    KEYMASTER_PROVISION_ATTEST_KEY = KEYMASTER_UTILS_CMD_ID + 9
    KEYMASTER_SET_VBH = KEYMASTER_UTILS_CMD_ID + 17
    KEYMASTER_GET_DATE_SUPPORT = KEYMASTER_UTILS_CMD_ID + 21
    KEYMASTER_FBE_SET_SEED = KEYMASTER_UTILS_CMD_ID + 24

    
    def setup(self, mu):
        self.addr = allocate_mock(0x80)
        self.stub_addr = allocate_mock(8 * len(self.funcs))
        
        # Setup QSEECom Protocol
        qsee_com_data = struct.pack("<Q", 0x0000000000010000)
        mu.mem_write(self.addr, qsee_com_data)
        
        # Setup stubs for QSEECom
        for i in range(len(self.funcs)):
            stub_addr = self.stub_addr + (i * 8)
            insn1 = defines.DYNAMIC_HOOK_BRK
            insn2 = 0xD65F03C0 # RET
            register_dynamic_hook(stub_addr, self, i)
            mu.mem_write(stub_addr, struct.pack("<II", insn1, insn2))
            # Write stub addresses to the protocol table (0..3)
            mu.mem_write(self.addr + self.funcs_offset + (i * 8), struct.pack("<Q", stub_addr))
        
        print(f"[UEFI] QSEECom Protocol at 0x{self.addr:X}")

    def handle_locate_protocol(self, mu, interface_ptr_ptr_addr):
        print("       -> Found requests for EFI_QSEE_COM_PROTOCOL, returning mock interface.")
        mu.mem_write(interface_ptr_ptr_addr, struct.pack("<Q", self.addr))
        return 0

    def handle_open_protocol(self, mu, handle, interface_ptr_ptr_addr):
        print("       -> [OpenProtocol] Returning mocked QSEECom Protocol.")
        mu.mem_write(interface_ptr_ptr_addr, struct.pack("<Q", self.addr))
        return 0
    
    def handle_hook(self, mu, func_idx):
        func_name = self.funcs[func_idx]
        if func_name == "QseecomStartApp":
            print(f"       -> [QSEECom] QseecomStartApp called: {read_string(mu, mu.reg_read(UC_ARM64_REG_X1))}")
            mu.reg_write(UC_ARM64_REG_X0, 0)
        elif func_name == "QseecomShutdownApp":
            print(f"       -> [QSEECom] QseecomShutdownApp called")
            mu.reg_write(UC_ARM64_REG_X0, 0)
        elif func_name == "QseecomSendCmd":
            req_ptr = mu.reg_read(UC_ARM64_REG_X2)
            req_len = mu.reg_read(UC_ARM64_REG_X3)
            res_ptr = mu.reg_read(UC_ARM64_REG_X4)
            res_len = mu.reg_read(UC_ARM64_REG_X5)
            req_data = mu.mem_read(req_ptr, req_len)
            cmd_id = struct.unpack("<I", req_data[:4])[0]
            print(f"       -> [QSEECom] QseecomSendCmd called, cmd_id: {cmd_id}")
            if cmd_id == self.KEYMASTER_GET_VERSION:
                if res_len >= 20:
                    mu.mem_write(res_ptr, struct.pack("<IIIII", 0, 2, 0, 0, 0))
            elif cmd_id == self.KEYMASTER_SET_ROT:
                RotOffset, RotSize = struct.unpack("<II", req_data[4:12])
                RotDigest = req_data[12:12+32]
                print(f"       -> [QSEECom] SetRot: Offset: {RotOffset}, Size: {RotSize}, Digest: {RotDigest.hex()}")

                mu.reg_write(UC_ARM64_REG_X0, 0)
            elif cmd_id == self.KEYMASTER_SET_BOOT_STATE:
                IsUnlocked = struct.unpack("<I", req_data[16:16+4])[0]
                PublicKey = req_data[16+4:16+4+32]
                Color, SystemVersion, SystemSecurityLevel = struct.unpack("<III", req_data[16+4+32:16+4+32+12])
                print(f"       -> [QSEECom] SetBootState called. IsUnlocked: {IsUnlocked}, PublicKey: {PublicKey.hex()}, Color: {Color}, SystemVersion: {SystemVersion}, SystemSecurityLevel: {SystemSecurityLevel}")

                mu.reg_write(UC_ARM64_REG_X0, 0)
            elif cmd_id == self.KEYMASTER_SET_VBH:
                VBHash = req_data[4:4+32]
                print(f"       -> [QSEECom] SetVBH called. VBHash: {VBHash.hex()}")

                mu.reg_write(UC_ARM64_REG_X0, 0)
            else:
                print(f"       -> [QSEECom] Unknown command: {cmd_id}")

            mu.reg_write(UC_ARM64_REG_X0, 0)
        elif func_name == "QseecomStartAppByGuid":
            print(f"       -> [QSEECom] QseecomStartAppByGuid called")
            mu.reg_write(UC_ARM64_REG_X0, 0)

"""
struct _QCOM_SCM_PROTOCOL {
  UINT64 Revision;
  QCOM_SCM_SYS_CALL ScmSysCall;
  QCOM_SCM_FAST_CALL_2 ScmFastCall2;
  QCOM_SCM_GET_VERSION ScmGetVersion;
  QCOM_SCM_REGISTER_CALLBACK ScmRegisterCallback;
  QCOM_SCM_SEND_COMMAND ScmSendCommand;
  QCOM_SCM_EXIT_BOOT_SERVICES ScmExitBootServicesHandler;
  QCOM_SCM_SIP_SYS_CALL ScmSipSysCall;
  QCOM_SCM_DEREGISTER_CALLBACK ScmDeRegisterCallback;
  QCOM_SCM_GET_CLIENT_ENV ScmGetClientEnv;
  QCOM_SCM_QSEE_SYS_CALL ScmQseeSysCall;
};

"""
class QcomScmProtocol(Protocol):
    def __init__(self):
        super().__init__(defines.QCOM_SCM_PROTOCOL_GUID)
        self.addr = 0
        self.stub_addr = 0
        self.funcs_offset = 8
        self.funcs = ["ScmSysCall", "ScmFastCall2", "ScmGetVersion", "ScmRegisterCallback", "ScmSendCommand", "ScmExitBootServicesHandler", "ScmSipSysCall", "ScmDeRegisterCallback", "ScmGetClientEnv", "ScmQseeSysCall"]
    
    TZ_INFO_GET_SECURE_STATE = 0x2000604
    DEBUG_RE_ENABLED_FUSE = 6

    def setup(self, mu):
        self.addr = allocate_mock(0x80)
        self.stub_addr = allocate_mock(8 * len(self.funcs))
        
        # Setup QCOM_SCM Protocol
        qcom_scm_data = struct.pack("<Q", 0x0000000000010000)
        mu.mem_write(self.addr, qcom_scm_data)
        
        # Setup stubs for QCOM_SCM
        for i in range(len(self.funcs)):
            stub_addr = self.stub_addr + (i * 8)
            insn1 = defines.DYNAMIC_HOOK_BRK
            insn2 = 0xD65F03C0 # RET
            register_dynamic_hook(stub_addr, self, i)
            mu.mem_write(stub_addr, struct.pack("<II", insn1, insn2))
            # Write stub addresses to the protocol table (0..3)
            mu.mem_write(self.addr + self.funcs_offset + (i * 8), struct.pack("<Q", stub_addr))
        
        print(f"[UEFI] QCOM_SCM Protocol at 0x{self.addr:X}")
    
    def handle_locate_protocol(self, mu, interface_ptr_ptr_addr):
        print("       -> Found requests for EFI_QCOM_SCM_PROTOCOL, returning mock interface.")
        mu.mem_write(interface_ptr_ptr_addr, struct.pack("<Q", self.addr))
        return 0

    def handle_open_protocol(self, mu, handle, interface_ptr_ptr_addr):
        print("       -> [OpenProtocol] Returning mocked QCOM_SCM Protocol.")
        mu.mem_write(interface_ptr_ptr_addr, struct.pack("<Q", self.addr))
        return 0

    def handle_hook(self, mu, func_idx):
        func_name = self.funcs[func_idx]
        if func_name == "ScmSysCall":
            print(f"       -> [QCOM_SCM] ScmSysCall called")
            mu.reg_write(UC_ARM64_REG_X0, 0)
        elif func_name == "ScmFastCall2":
            print(f"       -> [QCOM_SCM] ScmFastCall2 called")
            mu.reg_write(UC_ARM64_REG_X0, 0)
        elif func_name == "ScmGetVersion":
            print(f"       -> [QCOM_SCM] ScmGetVersion called")
            mu.reg_write(UC_ARM64_REG_X0, 0)
        elif func_name == "ScmRegisterCallback":
            print(f"       -> [QCOM_SCM] ScmRegisterCallback called")
            mu.reg_write(UC_ARM64_REG_X0, 0)
        elif func_name == "ScmSendCommand":
            print(f"       -> [QCOM_SCM] ScmSendCommand called")
            mu.reg_write(UC_ARM64_REG_X0, 0)
        elif func_name == "ScmExitBootServicesHandler":
            print(f"       -> [QCOM_SCM] ScmExitBootServicesHandler called")
            mu.reg_write(UC_ARM64_REG_X0, 0)
        elif func_name == "ScmSipSysCall":
            smc_id = mu.reg_read(UC_ARM64_REG_X1)
            print(f"       -> [QCOM_SCM] ScmSipSysCall called. smc_id: 0x{smc_id:X}")
            param_id = mu.reg_read(UC_ARM64_REG_X2)
            parameters_ptr = mu.reg_read(UC_ARM64_REG_X3)
            results_ptr = mu.reg_read(UC_ARM64_REG_X4)

            if smc_id == self.TZ_INFO_GET_SECURE_STATE:
                mu.mem_write(results_ptr, struct.pack("<QQQ", 1, 1 << self.DEBUG_RE_ENABLED_FUSE, 0))
            else:
                print(f"       -> [QCOM_SCM] Unknown SMC ID: 0x{smc_id:X}")

            mu.reg_write(UC_ARM64_REG_X0, 0)
        elif func_name == "ScmDeRegisterCallback":
            print(f"       -> [QCOM_SCM] ScmDeRegisterCallback called")
            mu.reg_write(UC_ARM64_REG_X0, 0)
        elif func_name == "ScmGetClientEnv":
            print(f"       -> [QCOM_SCM] ScmGetClientEnv called")
            mu.reg_write(UC_ARM64_REG_X0, 0)
        elif func_name == "ScmQseeSysCall":
            print(f"       -> [QCOM_SCM] ScmQseeSysCall called")
            mu.reg_write(UC_ARM64_REG_X0, 0)

"""
struct _EFI_CHIPINFO_PROTOCOL {
  UINT64 Revision;
  EFI_DALCHIPINFO_GETCHIPVERSION GetChipVersion;
  EFI_DALCHIPINFO_GETRAWCHIPVERSION GetRawChipVersion;
  EFI_DALCHIPINFO_GETCHIPID GetChipId;
  EFI_DALCHIPINFO_GETRAWCHIPID GetRawChipId;
  EFI_DALCHIPINFO_GETCHIPIDSTRING GetChipIdString;
  EFI_DALCHIPINFO_GETCHIPFAMILY GetChipFamily;
  EFI_DALCHIPINFO_GETMODEMSUPPORT GetModemSupport;
  EFI_DALCHIPINFO_GETPROCESSORNAMESTRING GetProcessorNameString;
  EFI_DALCHIPINFO_GETSERIALNUMBER GetSerialNumber;
  EFI_DALCHIPINFO_GETFOUNDRYID GetFoundryId;
  EFI_DALCHIPINFO_GETRAWDEVICEFAMILY GetRawDeviceFamily;
  EFI_DALCHIPINFO_GETRAWDEVICENUMBER GetRawDeviceNumber;
  EFI_DALCHIPINFO_GETQFPROMCHIPID GetQFPROMChipId;
  EFI_DALCHIPINFO_GETMARKETINGNAMESTRING GetMarketingNameString;
  EFI_DALCHIPINFO_GETSUBSETPART GetSubsetPart;
  EFI_DALCHIPINFO_GETSUBSETCPUS GetSubsetCPUs;
  EFI_DALCHIPINFO_GETSKU GetSKU;
  EFI_CHIPINFO_GETNUMFUNCTIONALCLUSTERS GetNumFunctionalClusters;
  EFI_CHIPINFO_GETBOOTCLUSTERANDCORE GetBootClusterAndCore;
  EFI_CHIPINFO_GETDISABLEDFEATURES GetDisabledFeatures;
  EFI_CHIPINFO_ISPARTDISABLED IsPartDisabled;
  EFI_CHIPINFO_GETDISABLEDCPUS GetDisabledCPUs;
};
"""
class ChipInfoProtocol(Protocol):
    def __init__(self):
        super().__init__(defines.EFI_CHIPINFO_PROTOCOL_GUID)
        self.addr = 0
        self.funcs_offset = 8
        self.funcs = [
            "GetChipVersion",
            "GetRawChipVersion",
            "GetChipId",
            "GetRawChipId",
            "GetChipIdString",
            "GetChipFamily",
            "GetModemSupport",
            "GetProcessorNameString",
            "GetSerialNumber",
            "GetFoundryId",
            "GetRawDeviceFamily",
            "GetRawDeviceNumber",
            "GetQFPROMChipId",
            "GetMarketingNameString",
            "GetSubsetPart",
            "GetSubsetCPUs",
            "GetSKU",
            "GetNumFunctionalClusters",
            "GetBootClusterAndCore",
            "GetDisabledFeatures",
            "IsPartDisabled",
            "GetDisabledCPUs",
        ]
        self.chip_id = 0
        self.chip_version = 0

    def setup(self, mu, chip_id, chip_version):
        self.chip_id = chip_id
        self.chip_version = chip_version
        self.generate_hook_funcs(mu, struct.pack("<Q", 0x0000000000010000))
    
    def handle_hook(self, mu, func_idx):
        func_name = self.funcs[func_idx]
        if func_name == "GetChipVersion":
            mu.mem_write(mu.reg_read(UC_ARM64_REG_X1), struct.pack("<Q", self.chip_version))
            print(f"       -> [ChipInfo] GetChipVersion called")
            mu.reg_write(UC_ARM64_REG_X0, 0)
        elif func_name == "GetRawChipVersion":
            print(f"       -> [ChipInfo] GetRawChipVersion called")
            mu.reg_write(UC_ARM64_REG_X0, 0)
        elif func_name == "GetChipId":
            mu.mem_write(mu.reg_read(UC_ARM64_REG_X1), struct.pack("<Q", self.chip_id))
            print(f"       -> [ChipInfo] GetChipId called")
            mu.reg_write(UC_ARM64_REG_X0, 0)
        elif func_name == "GetRawChipId":
            print(f"       -> [ChipInfo] GetRawChipId called")
            mu.reg_write(UC_ARM64_REG_X0, 0)
        elif func_name == "GetChipIdString":
            print(f"       -> [ChipInfo] GetChipIdString called")
            mu.reg_write(UC_ARM64_REG_X0, 0)
        elif func_name == "GetChipFamily":
            print(f"       -> [ChipInfo] GetChipFamily called")
            mu.reg_write(UC_ARM64_REG_X0, 0)
        elif func_name == "GetModemSupport":
            print(f"       -> [ChipInfo] GetModemSupport called")
            mu.reg_write(UC_ARM64_REG_X0, 0)
        elif func_name == "GetProcessorNameString":
            print(f"       -> [ChipInfo] GetProcessorNameString called")
            mu.reg_write(UC_ARM64_REG_X0, 0)
        elif func_name == "GetSerialNumber":
            print(f"       -> [ChipInfo] GetSerialNumber called")
            mu.reg_write(UC_ARM64_REG_X0, 0)
        elif func_name == "GetFoundryId":
            print(f"       -> [ChipInfo] GetFoundryId called")
            mu.reg_write(UC_ARM64_REG_X0, 0)
        elif func_name == "GetRawDeviceFamily":
            print(f"       -> [ChipInfo] GetRawDeviceFamily called")
            mu.reg_write(UC_ARM64_REG_X0, 0)
        elif func_name == "GetRawDeviceNumber":
            print(f"       -> [ChipInfo] GetRawDeviceNumber called")
            mu.reg_write(UC_ARM64_REG_X0, 0)
        elif func_name == "GetQFPROMChipId":
            print(f"       -> [ChipInfo] GetQFPROMChipId called")
            mu.reg_write(UC_ARM64_REG_X0, 0)
        elif func_name == "GetMarketingNameString":
            print(f"       -> [ChipInfo] GetMarketingNameString called")
            mu.reg_write(UC_ARM64_REG_X0, 0)
        elif func_name == "GetSubsetPart":
            print(f"       -> [ChipInfo] GetSubsetPart called")
            mu.reg_write(UC_ARM64_REG_X0, 0)
        elif func_name == "GetSubsetCPUs":
            print(f"       -> [ChipInfo] GetSubsetCPUs called")
            mu.reg_write(UC_ARM64_REG_X0, 0)
        elif func_name == "GetSKU":
            print(f"       -> [ChipInfo] GetSKU called")
            mu.reg_write(UC_ARM64_REG_X0, 0)
        elif func_name == "GetNumFunctionalClusters":
            print(f"       -> [ChipInfo] GetNumFunctionalClusters called")
            mu.reg_write(UC_ARM64_REG_X0, 0)
        elif func_name == "GetBootClusterAndCore":
            print(f"       -> [ChipInfo] GetBootClusterAndCore called")
            mu.reg_write(UC_ARM64_REG_X0, 0)
        elif func_name == "GetDisabledFeatures":
            print(f"       -> [ChipInfo] GetDisabledFeatures called")
            mu.reg_write(UC_ARM64_REG_X0, 0)
        elif func_name == "IsPartDisabled":
            print(f"       -> [ChipInfo] IsPartDisabled called")
            mu.reg_write(UC_ARM64_REG_X0, 0)
        elif func_name == "GetDisabledCPUs":
            print(f"       -> [ChipInfo] GetDisabledCPUs called")
            mu.reg_write(UC_ARM64_REG_X0, 0)
        else:
            print(f"       -> [ChipInfo] Unknown function: {func_name}")
            mu.reg_write(UC_ARM64_REG_X0, 0)
            
"""
struct _EFI_PLATFORMINFO_PROTOCOL {
  UINT64 Version;
  EFI_PLATFORMINFO_GET_PLATFORMINFO GetPlatformInfo;
  EFI_PLATFORMINFO_GET_KEYVALUE GetKeyValue;
};
"""
class PlatformInfoProtocol(Protocol):
    def __init__(self):
        super().__init__(defines.EFI_PLATFORMINFO_PROTOCOL_GUID)
        self.addr = 0
        self.stubs_addr = 0
        self.funcs_offset = 8
        self.funcs = [
            "GetPlatformInfo",
            "GetKeyValue",
        ]

    def setup(self, mu):
        self.generate_hook_funcs(mu, struct.pack("<Q", 0x0000000000030000))

    def handle_hook(self, mu, func_idx):
        func_name = self.funcs[func_idx]
        if func_name == "GetPlatformInfo":
            data = struct.pack("<IIIBxxxI", 0xb, 0, 0, 0, 0)
            mu.mem_write(mu.reg_read(UC_ARM64_REG_X1), data)
            print(f"       -> [PlatformInfo] GetPlatformInfo called. {data.hex()}")
            mu.reg_write(UC_ARM64_REG_X0, 0)
        elif func_name == "GetKeyValue":
            print(f"       -> [PlatformInfo] GetKeyValue called")
            mu.reg_write(UC_ARM64_REG_X0, 0)
        else:
            print(f"       -> [PlatformInfo] Unknown function: {func_name}")
            mu.reg_write(UC_ARM64_REG_X0, 0)

class ResetReasonProtocol(Protocol):
    def __init__(self):
        super().__init__(defines.EFI_RESETREASON_PROTOCOL_GUID)
        self.addr = 0
        self.stubs_addr = 0
        self.funcs_offset = 8
        self.funcs = [
            "GetResetReason",
            "ClearResetReason",
        ]

    def setup(self, mu):
        self.generate_hook_funcs(mu, struct.pack("<Q", 0x0000000000010002))

    def handle_hook(self, mu, func_idx):
        global reset_reason
        func_name = self.funcs[func_idx]
        if func_name == "GetResetReason":
            """
            // Reboot modes
typedef enum {
  /* 0 - 31 Cold reset: Common defined features
   * 32 - 63 Cold Reset: OEM specific reasons
   * 64 - 254 - Reserved
   * 255 - Emergency download
   */
  NORMAL_MODE = 0x0,
  RECOVERY_MODE = 0x1,
  FASTBOOT_MODE = 0x2,
  ALARM_BOOT = 0x3,
  DM_VERITY_LOGGING = 0x4,
  DM_VERITY_ENFORCING = 0x5,
  DM_VERITY_KEYSCLEAR = 0x6,
  SILENT_MODE = 0xA,
  NON_SILENT_MODE = 0xB,
  FORCED_SILENT = 0xC,
  FORCED_NON_SILENT = 0xD,
  FIRMWARE_FAIL_SAFE = 0x0E,
  OEM_RESET_MIN = 0x20,
  OEM_RESET_MAX = 0x3f,
  EMERGENCY_DLOAD = 0xFF,
} RebootReasonType;
            """
            print(f"       -> [ResetReason] GetResetReason called. Returning {reset_reason}")
            mu.mem_write(mu.reg_read(UC_ARM64_REG_X1), struct.pack("<I", reset_reason))
            mu.reg_write(UC_ARM64_REG_X0, 0)
        elif func_name == "ClearResetReason":
            print(f"       -> [ResetReason] ClearResetReason called")
            mu.reg_write(UC_ARM64_REG_X0, 0)
        else:
            print(f"       -> [ResetReason] Unknown function: {func_name}")
            mu.reg_write(UC_ARM64_REG_X0, 0)