"""Helper module to generate benign synthetic test fixtures and archives for automated testing."""

import io
import struct
import tarfile
import zipfile
from pathlib import Path


def create_minimal_elf(
    arch: str = "x86_64",
    bitness: int = 64,
    endianness: str = "little",
    enable_nx: bool = True,
    has_relro: bool = False,
    is_pie: bool = False,
    is_relocatable: bool = False,
    custom_machine: int = None,
    symbols: list = None,
) -> bytes:
    """Construct a minimal valid synthetic ELF binary for parser verification."""
    # EI_MAG
    elf_bytes = bytearray(b"\x7fELF")

    # EI_CLASS (1 = 32-bit, 2 = 64-bit)
    elf_bytes.append(2 if bitness == 64 else 1)

    # EI_DATA (1 = 2's complement little endian, 2 = 2's complement big endian)
    is_little = endianness == "little"
    elf_bytes.append(1 if is_little else 2)

    # EI_VERSION (1 = EV_CURRENT)
    elf_bytes.append(1)

    # EI_OSABI (0 = ELFOSABI_NONE / System V)
    elf_bytes.append(0)

    # EI_ABIVERSION + padding (8 bytes)
    elf_bytes.extend(b"\x00" * 8)

    end_char = "<" if is_little else ">"

    # e_type (1 = ET_REL, 2 = ET_EXEC, 3 = ET_DYN)
    if is_relocatable:
        e_type = 1
    elif is_pie:
        e_type = 3
    else:
        e_type = 2

    # e_machine: 3 = 386, 40 = ARM, 8 = MIPS, 62 = x86_64, 183 = AARCH64
    if custom_machine is not None:
        e_machine = custom_machine
    else:
        machine_map = {"x86": 3, "arm": 40, "arm64": 183, "aarch64": 183, "mips": 8, "x86_64": 62}
        e_machine = machine_map.get(arch.lower(), 62)

    # Program header table setup
    ph_entries = []
    if not is_relocatable:
        # Entry 1: PT_LOAD (type = 1, flags = 5 (R|X))
        ph_entries.append({"type": 1, "flags": 5, "offset": 0, "vaddr": 0x400000, "filesz": 0x100, "memsz": 0x100})

        # Entry 2: PT_GNU_STACK (if enable_nx -> PF_R | PF_W = 6; if disabled -> PF_R | PF_W | PF_X = 7)
        stack_flags = 6 if enable_nx else 7
        ph_entries.append({"type": 0x6474e551, "flags": stack_flags, "offset": 0, "vaddr": 0, "filesz": 0, "memsz": 0})

        if has_relro:
            # PT_GNU_RELRO (type = 0x6474e552)
            ph_entries.append({"type": 0x6474e552, "flags": 4, "offset": 0, "vaddr": 0x400000, "filesz": 0x50, "memsz": 0x50})

    ph_count = len(ph_entries)

    if bitness == 64:
        # ELF64 header: 64 bytes
        # struct Elf64_Ehdr {
        #   Elf64_Half    e_type;        2 bytes
        #   Elf64_Half    e_machine;     2 bytes
        #   Elf64_Word    e_version;     4 bytes
        #   Elf64_Addr    e_entry;       8 bytes
        #   Elf64_Off     e_phoff;       8 bytes (start at 64)
        #   Elf64_Off     e_shoff;       8 bytes (0 for no sections)
        #   Elf64_Word    e_flags;       4 bytes
        #   Elf64_Half    e_ehsize;      2 bytes (64)
        #   Elf64_Half    e_phentsize;   2 bytes (56)
        #   Elf64_Half    e_phnum;       2 bytes (ph_count)
        #   Elf64_Half    e_shentsize;   2 bytes (64)
        #   Elf64_Half    e_shnum;       2 bytes (0)
        #   Elf64_Half    e_shstrndx;    2 bytes (0)
        # }
        ehdr = struct.pack(
            f"{end_char}HHIQQQIHHHHHH",
            e_type,
            e_machine,
            1,          # e_version
            0x400000,   # e_entry
            64 if ph_count > 0 else 0,  # e_phoff
            0,          # e_shoff
            0,          # e_flags
            64,         # e_ehsize
            56 if ph_count > 0 else 0,  # e_phentsize
            ph_count,   # e_phnum
            64,         # e_shentsize
            0,          # e_shnum
            0,          # e_shstrndx
        )
        elf_bytes.extend(ehdr)

        # Write program headers (Elf64_Phdr is 56 bytes)
        # Elf64_Word p_type; Elf64_Word p_flags; Elf64_Off p_offset; Elf64_Addr p_vaddr;
        # Elf64_Addr p_paddr; Elf64_Xword p_filesz; Elf64_Xword p_memsz; Elf64_Xword p_align;
        for ph in ph_entries:
            phdr = struct.pack(
                f"{end_char}IIQQQQQQ",
                ph["type"],
                ph["flags"],
                ph["offset"],
                ph["vaddr"],
                ph["vaddr"],
                ph["filesz"],
                ph["memsz"],
                0x1000,
            )
            elf_bytes.extend(phdr)

    else:
        # ELF32 header: 52 bytes
        ehdr = struct.pack(
            f"{end_char}HHIIIIIHHHHHH",
            e_type,
            e_machine,
            1,
            0x100000,
            52,  # e_phoff
            0,
            0,
            52,  # e_ehsize
            32,  # e_phentsize
            ph_count,
            40,
            0,
            0,
        )
        elf_bytes.extend(ehdr)

        # Elf32_Phdr is 32 bytes
        # Elf32_Word p_type; Elf32_Off p_offset; Elf32_Addr p_vaddr; Elf32_Addr p_paddr;
        # Elf32_Word p_filesz; Elf32_Word p_memsz; Elf32_Word p_flags; Elf32_Word p_align;
        for ph in ph_entries:
            phdr = struct.pack(
                f"{end_char}IIIIIIII",
                ph["type"],
                ph["offset"],
                ph["vaddr"],
                ph["vaddr"],
                ph["filesz"],
                ph["memsz"],
                ph["flags"],
                0x1000,
            )
            elf_bytes.extend(phdr)

    # Pad with dummy code
    elf_bytes.extend(b"\x90" * 64)
    return bytes(elf_bytes)


def create_benign_firmware_archive(output_path: Path, archive_type: str = "tar.gz"):
    """Create a benign test firmware archive containing configs, shadow, scripts, and synthetic ELFs."""
    elf_nx_on = create_minimal_elf("mips", bitness=32, endianness="big", enable_nx=True, has_relro=True)
    elf_nx_off = create_minimal_elf("arm", bitness=32, endianness="little", enable_nx=False, is_pie=False)

    files = {
        "etc/init.d/rcS": b"#!/bin/sh\necho 'Starting benign IoT device services...'\n/bin/busybox --install\n",
        "etc/shadow": b"root:$6$saltsalt$dummyhashvaluehere1234567890abcdefghijklmnopqrstuv:19000:0:99999:7:::\n",
        "etc/config.json": b'{"device": "RouterX", "api_key": "AKIAIOSFODNN7EXAMPLE", "crypto": "MD5_Init"}\n',
        "bin/service_mips": elf_nx_on,
        "bin/daemon_arm": elf_nx_off,
        "www/index.html": b"<html><body><h1>Router Admin</h1></body></html>\n",
    }

    if archive_type == "zip":
        with zipfile.ZipFile(output_path, "w") as zf:
            for name, content in files.items():
                zf.writestr(name, content)
    else:
        with tarfile.open(output_path, "w:gz") as tf:
            for name, content in files.items():
                ti = tarfile.TarInfo(name=name)
                ti.size = len(content)
                tf.addfile(ti, io.BytesIO(content))

