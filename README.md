# ablemu

`ablemu` is a Qualcomm ABL (Android Bootloader) ARM64 emulator based on the [Unicorn Engine](https://www.unicorn-engine.org/). It provides a minimal UEFI environment to execute, trace, and debug ABL PE files (typically `LinuxLoader.efi` or `abl.elf`). It is suitable for security reasearch.

## Features

- **Fastboot commands**: Supports feeding fastboot commands.
- **UEFI Environment**: 
    - Minimal `EFI_SYSTEM_TABLE` and `EFI_BOOT_SERVICES` stubs.
    - Simplified stack and heap management.
- **Protocol Mocking**: Implements various UEFI protocols required by ABL, including:
    - `BlockIO`, `DevicePath`, `PartitionEntry`
    - `VerifiedBoot`, `KernelInterface`
    - `ChipInfo`, `PlatformInfo`, `ResetReason`
    - `QSEECom`, `QcomScm`, and more.
- **Boot Support**: Capable of "loading" a Linux kernel and DTB (stubs the loading process).
- **Integrated Debugger**: An interactive console for step execution, register inspection, and stack scanning.
- **Tracing**: Optional per-instruction tracing for deep analysis.

## Requirements

- Python 3.12+
- `unicorn`
- `pefile`

## Installation

```bash
# Install dependencies
pip install -r requirements.txt
```

## Usage

Place your `abl.elf` (or `abl.img`, `LinuxLoader.efi`) in the project root or provide the path. Optionally place other partitions like "boot", "vbmeta" or "devinfo" to emulate boot sequence and AVB verification.

```bash
# Run the emulator
python emu.py abl.elf
```

```
$ python emu.py abl.elf --feed-cmd "getvar:all" --reset-reason 2 | grep -ai usb
       -> Found requests for EFI_USB_DEVICE_PROTOCOL, returning specific mock interface.
[UEFI] UsbDevice::AllocateTransferBuffer | Args: 0x2300000, 0x7EFFF8E8, 0x7EFFF758, 0x0, 0x7EFFF9AC, 0x4
       -> [GetVariable] VariableName: 'UsbfnMaxSpeed' GUID: QCOM
[UEFI] UsbDevice::StartEx | Args: 0x98958, 0x806E8, 0x0, 0x7EFFFA88, 0x7EFFFA94, 0xDE013000
       -> [UsbDevice::StartEx] Starting USB device with descriptor set at 0x98958
...
[UEFI] UsbDevice::Send | Args: 0x81, 0x15, 0xA3300000, 0x0, 0x1, 0x0
       -> [UsbDevice::Send] Send 21 bytes on endpoint 129 from 0xA3300000
       -> [UsbDevice::Send] Data: INFOhw-revision:10000
[UEFI] UsbDevice::HandleEvent | Args: 0x7EFFF82C, 0x7EFFF820, 0x7EFFF830, 0x0, 0x1, 0x0
       -> [UsbDevice::HandleEvent] Returning event type 2
[UEFI] UsbDevice::Send | Args: 0x81, 0x12, 0xA3300000, 0x0, 0x1, 0x0
       -> [UsbDevice::Send] Send 18 bytes on endpoint 129 from 0xA3300000
       -> [UsbDevice::Send] Data: INFOfactory-mode:1
...
```

Tested on Y700 gen4 TB322FC (ZUXOS_1.5.10.063_260111_PRC). emu.py currently embeds some addresses for Y700 gen4 to log internal behaviors, but it is not neccessary for emulation.

### Environment Variables

- `EMU_TRACE=1`: Enable per-instruction tracing.
- `EMU_DEBUG=1`: Start in interactive debug mode.
- `EMU_LOG_OFF=1`: Disable verbose logging for certain UEFI services.

### Interactive Debugger Commands

When in debug mode (or when a breakpoint is hit), you can use the following commands:

- `s`: Step into the next instruction.
- `c`: Continue execution.
- `r`: Dump general-purpose registers.
- `t`: Heuristic stack trace (scans the stack for return addresses).
- `u <addr> <size>`: Un-pause/Continue from a specific address.
- `q`: Quit the emulator.

## Project Structure

- `emu.py`: Main emulator entry point and UEFI logic.
- `defines.py`: Constants, GUIDs, and memory map definitions.
- `utils.py`: Utility functions for memory allocation, string reading, and hooking.
- `partitions.py`: Partition list and LBA mapping for storage emulation.
- `protocols.py`: Implementations of various UEFI protocols.
- `format_string.py`: Minimal `printf` style formatter for UEFI logs.

## License

MIT

## Acknowledgments

- [Unicorn Engine](https://www.unicorn-engine.org/)
- [codelinaro opensource abl](https://git.codelinaro.org/clo/la/abl/tianocore/edk2)