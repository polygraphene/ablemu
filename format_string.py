from unicorn import Uc

# Process format string with arguments
def process_format_string(mu: Uc, fmt: str, args: list) -> str:
    """Process a printf-style format string with arguments."""
    result = ""
    arg_idx = 0
    i = 0
    while i < len(fmt):
        if fmt[i] == '%' and i + 1 < len(fmt):
            while fmt[i + 1].isdigit():
                i += 1
            long = False
            longlong = False
            if fmt[i + 1] == 'l':
                long = True
                i += 1
            if fmt[i + 1] == 'l':
                longlong = True
                long = False
                i += 1
            spec = fmt[i + 1]
            if spec == 'd' or spec == 'i':
                # Signed decimal integer
                if arg_idx < len(args):
                    val = args[arg_idx]
                    # Sign extend if needed
                    if long or longlong:
                        if val & 0x8000000000000000:
                            val = -(0x10000000000000000 - val)
                    else:
                        if val & 0x80000000:
                            val = -(0x100000000 - val)
                    result += str(val)
                    arg_idx += 1
            elif spec == 'u':
                # Unsigned decimal integer
                if arg_idx < len(args):
                    if long or longlong:
                        result += str(args[arg_idx] & 0xFFFFFFFFFFFFFFFF)
                    else:
                        result += str(args[arg_idx] & 0xFFFFFFFF)
                    arg_idx += 1
            elif spec == 'x' or spec == 'X':
                # Hexadecimal
                if arg_idx < len(args):
                    if long or longlong:
                        result += f"{args[arg_idx]:X}" if spec == 'X' else f"{args[arg_idx]:x}"
                    else:
                        result += f"{args[arg_idx]:X}" if spec == 'X' else f"{args[arg_idx]:x}"
                    arg_idx += 1
            elif spec == 's':
                # UTF-16LE string
                if arg_idx < len(args):
                    str_addr = args[arg_idx]
                    try:
                        s_bytes = bytearray()
                        for j in range(0, 512, 2):
                            c1 = mu.mem_read(str_addr + j, 1)[0]
                            if j + 1 < 512:
                                c2 = mu.mem_read(str_addr + j + 1, 1)[0]
                            else:
                                c2 = 0
                            if c1 == 0 and c2 == 0:
                                break
                            s_bytes.append(c1)
                            s_bytes.append(c2)
                        result += s_bytes.decode('utf-16le', errors='replace').strip()
                    except:
                        result += "<error reading UTF-16LE string>"
                    arg_idx += 1
            elif spec == 'a':
                # ASCII string
                if arg_idx < len(args):
                    str_addr = args[arg_idx]
                    try:
                        s_bytes = bytearray()
                        for j in range(256):
                            c = mu.mem_read(str_addr + j, 1)[0]
                            if c == 0:
                                break
                            s_bytes.append(c)
                        result += s_bytes.decode('ascii', errors='replace').strip()
                    except:
                        result += "<error reading ASCII string>"
                    arg_idx += 1
            elif spec == 'r':
                # EFI_STATUS return value (hexadecimal)
                if arg_idx < len(args):
                    status_val = args[arg_idx]
                    # EFI_STATUS error codes have bit 63 set (high bit)
                    if status_val & 0x8000000000000000:
                        # Error status - show human-readable error name
                        error_map = {
                            0x8000000000000001: "EFI_LOAD_ERROR",
                            0x8000000000000002: "EFI_INVALID_PARAMETER",
                            0x8000000000000003: "EFI_UNSUPPORTED",
                            0x8000000000000004: "EFI_BAD_BUFFER_SIZE",
                            0x8000000000000005: "EFI_BUFFER_TOO_SMALL",
                            0x8000000000000006: "EFI_NOT_READY",
                            0x8000000000000007: "EFI_DEVICE_ERROR",
                            0x8000000000000008: "EFI_WRITE_PROTECTED",
                            0x8000000000000009: "EFI_OUT_OF_RESOURCES",
                            0x800000000000000A: "EFI_VOLUME_CORRUPTED",
                            0x800000000000000B: "EFI_VOLUME_FULL",
                            0x800000000000000C: "EFI_NO_MEDIA",
                            0x800000000000000D: "EFI_MEDIA_CHANGED",
                            0x800000000000000E: "EFI_NOT_FOUND",
                            0x800000000000000F: "EFI_ACCESS_DENIED",
                            0x8000000000000010: "EFI_NO_RESPONSE",
                            0x8000000000000011: "EFI_NO_MAPPING",
                            0x8000000000000012: "EFI_TIMEOUT",
                            0x8000000000000013: "EFI_NOT_STARTED",
                            0x8000000000000014: "EFI_ALREADY_STARTED",
                            0x8000000000000015: "EFI_ABORTED",
                            0x8000000000000016: "EFI_ICMP_ERROR",
                            0x8000000000000017: "EFI_TFTP_ERROR",
                            0x8000000000000018: "EFI_PROTOCOL_ERROR",
                            0x8000000000000019: "EFI_INCOMPATIBLE_VERSION",
                            0x800000000000001A: "EFI_SECURITY_VIOLATION",
                            0x800000000000001B: "EFI_CRC_ERROR",
                            0x800000000000001C: "EFI_END_OF_MEDIA",
                            0x800000000000001D: "EFI_END_OF_FILE",
                            0x800000000000001E: "EFI_INVALID_LANGUAGE",
                            0x800000000000001F: "EFI_COMPROMISED_DATA",
                            0x8000000000000020: "EFI_HTTP_ERROR",
                        }
                        if status_val in error_map:
                            result += error_map[status_val]
                        else:
                            result += f"EFI_ERROR(0x{status_val:016X})"
                    else:
                        # Success status
                        if status_val == 0:
                            result += "EFI_SUCCESS"
                        else:
                            result += f"0x{status_val:016X}"
                    arg_idx += 1
            elif spec == 'g':
                # GUID
                if arg_idx < len(args):
                    guid_addr = args[arg_idx]
                    try:
                        guid_bytes = mu.mem_read(guid_addr, 16)
                        guid_str = "{}-{}-{}-{}-{}".format(
                            guid_bytes[0:4].hex(),
                            guid_bytes[4:6].hex(),
                            guid_bytes[6:8].hex(),
                            guid_bytes[8:10].hex(),
                            guid_bytes[10:16].hex()
                        )
                        result += guid_str
                    except:
                        result += "<error reading GUID>"
                    arg_idx += 1
            elif spec == '%':
                result += '%'
            else:
                result += fmt[i:i+2]
            i += 2
        else:
            result += fmt[i]
            i += 1
    return result