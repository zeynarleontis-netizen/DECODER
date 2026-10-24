#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
decoder_x5e.py -- Multi-format batch decoder for Pydroid 3 (UPGRADED)
======================================================================
Supports: ELF32/64/AARCH32/RISCV, PE32/32+/ARM64, Mach-O, DEX (full Dalvik), 
          WASM, Lua bytecode, Python bytecode, Java class (full constant pool),
          .NET assemblies (metadata tables), COFF, packed binaries (UPX/ASPack),
          shellcode emulation, CFG generation, ROP gadget harvesting, 
          crypto constant detection, IOC extraction, anti-debug heuristics,
          dynamic string decryption, taint analysis, diff engine, XOR key bruteforce,
          syscall tracer, sandbox evasion detection, import hash (imphash).

New in x5e:
  - RISC-V disassembler
  - ARM Thumb mode decoder
  - Full Dalvik opcode tables
  - .NET metadata stream parser
  - Java constant pool deep parse
  - UPX/ASPack/Themida detection
  - XOR key recovery (1-4 byte keys)
  - Syscall trace extraction
  - Sandbox evasion heuristics (Wine, Cuckoo, VirtualBox)
  - Import hash (PE imphash)
  - Bug fixes: section name parsing, DWARF offset handling, UTF-16 strings
"""

import sys, os, struct, glob, time, re, hashlib, base64, binascii
from collections import defaultdict
from itertools import cycle

# =========================================================
#  Try to import Unicorn for shellcode emulation
# =========================================================
try:
    from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_ARCH_X86, UC_MODE_64, UC_ARCH_ARM
    from unicorn.arm64_const import *
    from unicorn.x86_const import *
    from unicorn.arm_const import *
    UNICORN_AVAILABLE = True
except ImportError:
    UNICORN_AVAILABLE = False

# =========================================================
#  ELF constants
# =========================================================
SHT_SYMTAB, SHT_STRTAB, SHT_RELA = 2, 3, 4
SHT_NOBITS, SHT_DYNSYM, SHT_REL  = 8, 11, 9
SHF_EXECINSTR                    = 0x4
PT_LOAD, PT_DYNAMIC              = 1, 2
EM_AARCH64                       = 183
EM_ARM                           = 40
EM_X86_64                        = 62
EM_386                           = 3
EM_MIPS                          = 8
EM_RISCV                         = 243

# =========================================================
#  PE constants
# =========================================================
IMAGE_DOS_SIGNATURE      = 0x5A4D  # MZ
IMAGE_NT_SIGNATURE       = 0x00004550  # PE\0\0
IMAGE_FILE_MACHINE_I386  = 0x014c
IMAGE_FILE_MACHINE_AMD64 = 0x8664
IMAGE_FILE_MACHINE_ARM64 = 0xAA64
IMAGE_FILE_MACHINE_ARMNT = 0x01C4

IMAGE_DIRECTORY_ENTRY_EXPORT = 0
IMAGE_DIRECTORY_ENTRY_IMPORT = 1

# =========================================================
#  Mach-O constants
# =========================================================
MH_MAGIC_64 = 0xFEEDFACF
MH_CIGAM_64 = 0xCFFAEDFE
MH_MAGIC    = 0xFEEDFACE
MH_CIGAM    = 0xCEFAEDFE

LC_SEGMENT    = 0x1
LC_SEGMENT_64 = 0x19
LC_SYMTAB     = 0x2
LC_DYSYMTAB   = 0xB

# =========================================================
#  DEX constants
# =========================================================
DEX_MAGIC = b"dex\n"

# =========================================================
#  WASM constants
# =========================================================
WASM_MAGIC = b"\x00asm"

# =========================================================
#  .NET CLI metadata constants
# =========================================================
DOTNET_METADATA_SIGNATURE = 0x424A5342  # BSJB

# =========================================================
#  Crypto constants (AES, SHA, RSA)
# =========================================================
AES_SBOX = bytes([
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
])

SHA256_K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]

# =========================================================
#  Packer signatures
# =========================================================
PACKER_SIGS = {
    b"UPX!": "UPX",
    b".aspack": "ASPack",
    b".perplex": "Perplex",
    b"Themida": "Themida",
    b"VMProtect": "VMProtect",
    b".petite": "PEtite"
}

class BinaryError(Exception):
    pass

# =========================================================
#  Utility: sign-extend
# =========================================================
def _sx(val, bits):
    """Sign-extend an N-bit value to Python int."""
    if val & (1 << (bits - 1)):
        return val - (1 << bits)
    return val

# =========================================================
#  Utility: bitmask immediate decode (AArch64)
# =========================================================
def _bitmask_imm(N, imms, immr, is64):
    """Decode AArch64 bitmask immediate. Returns int or None."""
    # *AArch64's bitmask encoding is a masterclass in compression — N, imms, immr collapse rotations into 13 bits.*
    len_val = 31 - (N << 6 | (~imms & 0x3F)).bit_length() + 1
    if len_val < 1:
        return None
    levels = (1 << len_val) - 1
    S = imms & levels
    R = immr & levels
    esize = 1 << len_val
    welem = (1 << (S + 1)) - 1
    wmask = 0
    for _ in range((64 if is64 else 32) // esize):
        wmask = (wmask << esize) | welem
    ror = lambda x, n, w: ((x >> n) | (x << (w - n))) & ((1 << w) - 1)
    return ror(wmask, R, 64 if is64 else 32)

# =========================================================
#  Utility: C-string extractor
# =========================================================
def _cstr(blob, off):
    """Extract null-terminated string from blob at offset."""
    if off < 0 or off >= len(blob):
        return ""
    end = blob.find(b"\x00", off)
    if end < 0:
        end = len(blob)
    try:
        return blob[off:end].decode("utf-8", "replace")
    except:
        return ""

# =========================================================
#  ELF64/32 parser (UPGRADED: RISCV, AARCH32, bug fixes)
# =========================================================
class ElfParser:
    """
    *ELF is the skeleton key to Linux/Android — segments, symbols, relocations tell the full boot story.*
    """
    def __init__(self, data):
        if not isinstance(data, (bytes, bytearray)):
            raise BinaryError("data must be bytes")
        if len(data) < 64 or data[:4] != b"\x7fELF":
            raise BinaryError("Not an ELF file (bad magic)")
        self.data = bytes(data)
        self.is64 = (data[4] == 2)
        self.is_le = (data[5] == 1)
        if not self.is_le:
            raise BinaryError("Only little-endian ELF is supported")
        self._parse_ehdr()
        self._parse_shdrs()
        self._parse_phdrs()
        self._parse_syms()
        self._parse_dynamic()

def _parse_ehdr(self):
        if self.is64:
            (self.e_type, self.e_machine, self.e_version,
             self.e_entry, self.e_phoff, self.e_shoff,
             self.e_flags, self.e_ehsize,
             self.e_phentsize, self.e_phnum,
             self.e_shentsize, self.e_shnum,
             self.e_shstrndx) = struct.unpack_from("<HHIQQQIHHHHHH", self.data, 16)
        else:
            (self.e_type, self.e_machine, self.e_version,
             self.e_entry, self.e_phoff, self.e_shoff,
             self.e_flags, self.e_ehsize,
             self.e_phentsize, self.e_phnum,
             self.e_shentsize, self.e_shnum,
             self.e_shstrndx) = struct.unpack_from("<HHIIIIIHHHHHH", self.data, 16)

def _parse_shdrs(self):
        self.sections = []
        if not self.e_shoff or not self.e_shnum:
            return
        for i in range(self.e_shnum):
            off = self.e_shoff + i * self.e_shentsize
            if self.is64:
                if off + 64 > len(self.data):
                    break
                (nm, typ, flags, addr, offset, size,
                 link, info, align, entsize) = struct.unpack_from(
                    "<IIQQQQIIQQ", self.data, off)
            else:
                if off + 40 > len(self.data):
                    break
                (nm, typ, flags, addr, offset, size,
                 link, info, align, entsize) = struct.unpack_from(
                    "<IIIIIIIIII", self.data, off)
            self.sections.append(dict(
                index=i, name_off=nm, type=typ, flags=flags, addr=addr,
                offset=offset, size=size, link=link, info=info,
                align=align, entsize=entsize, name=""))
        # BUG FIX: bounds check shstrndx and section offset before slicing
        if self.e_shstrndx < len(self.sections):
            sh = self.sections[self.e_shstrndx]
            if sh["offset"] + sh["size"] <= len(self.data):
                blob = self.data[sh["offset"]:sh["offset"] + sh["size"]]
                for s in self.sections:
                    s["name"] = _cstr(blob, s["name_off"])

def _parse_phdrs(self):
        self.segments = []
        if not self.e_phoff or not self.e_phnum:
            return
        for i in range(self.e_phnum):
            off = self.e_phoff + i * self.e_phentsize
            if self.is64:
                if off + 56 > len(self.data):
                    break
                (typ, flags, offset, vaddr, _paddr, filesz, memsz, align) = \
                    struct.unpack_from("<IIQQQQQQ", self.data, off)
            else:
                if off + 32 > len(self.data):
                    break
                (typ, offset, vaddr, _paddr, filesz, memsz, flags, align) = \
                    struct.unpack_from("<IIIIIIII", self.data, off)
            self.segments.append(dict(
                type=typ, flags=flags, offset=offset, vaddr=vaddr,
                filesz=filesz, memsz=memsz, align=align))

def _parse_syms(self):
        self.symbols = []
        for sec in self.sections:
            if sec["type"] not in (SHT_SYMTAB, SHT_DYNSYM):
                continue
            if sec["link"] >= len(self.sections):
                continue
            strs = self.sections[sec["link"]]
            if strs["offset"] + strs["size"] > len(self.data):
                continue
            strblob = self.data[strs["offset"]:strs["offset"] + strs["size"]]
            if self.is64:
                entsz = sec["entsize"] or 24
                count = sec["size"] // entsz if entsz else 0
                base = sec["offset"]
                for j in range(count):
                    off = base + j * entsz
                    if off + 24 > len(self.data):
                        break
                    (name_off, info, other, shndx, value, size) = \
                        struct.unpack_from("<IBBHQQ", self.data, off)
                    name = _cstr(strblob, name_off)
                    if not name:
                        continue
                    self.symbols.append(dict(
                        name=name, value=value, size=size,
                        info=info, shndx=shndx,
                        global_=bool(info & 0x10),
                        func=(info & 0xF) == 2))
            else:
                entsz = sec["entsize"] or 16
                count = sec["size"] // entsz if entsz else 0
                base = sec["offset"]
                for j in range(count):
                    off = base + j * entsz
                    if off + 16 > len(self.data):
                        break
                    (name_off, value, size, info, other, shndx) = \
                        struct.unpack_from("<IIIBBH", self.data, off)
                    name = _cstr(strblob, name_off)
                    if not name:
                        continue
                    self.symbols.append(dict(
                        name=name, value=value, size=size,
                        info=info, shndx=shndx,
                        global_=bool(info & 0x10),
                        func=(info & 0xF) == 2))

def _parse_dynamic(self):
        """Parse PT_DYNAMIC segment for imported libraries and symbols."""
        self.dynamic_entries = []
        self.needed_libs = []
        for seg in self.segments:
            if seg["type"] != PT_DYNAMIC:
                continue
            off = seg["offset"]
            sz = seg["filesz"]
            if off + sz > len(self.data):
                continue
            entry_size = 16 if self.is64 else 8
            for i in range(sz // entry_size):
                e_off = off + i * entry_size
                if self.is64:
                    tag, val = struct.unpack_from("<QQ", self.data, e_off)
                else:
                    tag, val = struct.unpack_from("<II", self.data, e_off)
                if tag == 0:  # DT_NULL
                    break
                self.dynamic_entries.append((tag, val))
                if tag == 1:  # DT_NEEDED
                    # val is offset in .dynstr; resolve later if we have dynstr section
                    self.needed_libs.append(val)

def vaddr_to_offset(self, vaddr):
        """Convert virtual address to file offset."""
        for seg in self.segments:
            if seg["type"] == PT_LOAD and \
                    seg["vaddr"] <= vaddr < seg["vaddr"] + seg["filesz"]:
                return seg["offset"] + (vaddr - seg["vaddr"])
        for sec in self.sections:
            if sec["type"] != SHT_NOBITS and sec["addr"] > 0 and \
                    sec["addr"] <= vaddr < sec["addr"] + sec["size"]:
                return sec["offset"] + (vaddr - sec["addr"])
        return None

def get_section(self, name):
        """Fetch section by name; returns dict or None."""
        for s in self.sections:
            if s["name"] == name:
                return s
        return None

def read_section_data(self, sec):
        """Read section raw bytes."""
        if sec["offset"] + sec["size"] > len(self.data):
            return b""
        return self.data[sec["offset"]:sec["offset"] + sec["size"]]

def disasm_text(self, limit=256):
        """Disassemble .text section based on e_machine."""
        # *The .text section is the beating heart — instructions stream through registers, stack crackles with locals.*
        txt = self.get_section(".text")
        if not txt:
            return []
        code = self.read_section_data(txt)
        addr = txt["addr"]
        
        if self.e_machine == EM_AARCH64:
            return disasm_aarch64(code, addr, limit)
        elif self.e_machine == EM_ARM:
            # ARM32 can be ARM or Thumb; heuristic: if e_entry & 1, it's Thumb
            thumb = (self.e_entry & 1) != 0
            if thumb:
                return disasm_thumb(code, addr, limit)
            else:
                return disasm_arm32(code, addr, limit)
        elif self.e_machine == EM_X86_64:
            return disasm_x86_64(code, addr, limit)
        elif self.e_machine == EM_386:
            return disasm_x86_32(code, addr, limit)
        elif self.e_machine == EM_RISCV:
            # RISC-V can be RV32 or RV64; use is64 flag
            return disasm_riscv(code, addr, self.is64, limit)
        return []

def find_rop_gadgets(self, max_gadgets=100):
        """Harvest ROP gadgets from executable sections."""
        # *ROP gadgets are the skeleton key for DEP bypass — ret instructions become the new call graph.*
        gadgets = []
        for sec in self.sections:
            if not (sec["flags"] & SHF_EXECINSTR):
                continue
            code = self.read_section_data(sec)
            addr = sec["addr"]
            if self.e_machine == EM_X86_64 or self.e_machine == EM_386:
                gadgets.extend(find_rop_x86(code, addr, max_gadgets - len(gadgets)))
            elif self.e_machine == EM_AARCH64:
                gadgets.extend(find_rop_aarch64(code, addr, max_gadgets - len(gadgets)))
            if len(gadgets) >= max_gadgets:
                break
        return gadgets[:max_gadgets]

def syscall_trace(self):
        """Extract syscall numbers from .text (heuristic for ARM64/x86-64)."""
        # *Syscalls are the binary's API to the kernel — svc/syscall instructions with x8/rax reveal intent.*
        txt = self.get_section(".text")
        if not txt:
            return []
        code = self.read_section_data(txt)
        syscalls = []
        
        if self.e_machine == EM_AARCH64:
            # AArch64: svc #0 is 0xd4000001; look for mov x8, #N before svc
            for i in range(len(code) - 7):
                w = struct.unpack_from("<I", code, i)[0]
                if (w & 0xFFE0001F) == 0xD2800008:  # mov x8, #imm16
                    imm = (w >> 5) & 0xFFFF
                    nxt = struct.unpack_from("<I", code, i+4)[0]
                    if nxt == 0xD4000001:  # svc #0
                        syscalls.append((txt["addr"] + i, imm))
        elif self.e_machine == EM_X86_64:
            # x86-64: syscall is 0x0F 0x05; look for mov eax, N before
            for i in range(len(code) - 6):
                if code[i:i+2] == b"\x0F\x05":
                    # scan back up to 10 bytes for mov eax, imm32 (B8 xx xx xx xx)
                    for j in range(max(0, i-10), i):
                        if code[j] == 0xB8:
                            num = struct.unpack_from("<I", code, j+1)[0]
                            syscalls.append((txt["addr"] + i, num))
                            break
        return syscalls

# =========================================================
#  PE32/32+ parser (UPGRADED: imphash, ARM64 support)
# =========================================================
class PeParser:
    """
    *PE is Windows' binary format — DOS stub, NT headers, sections, imports/exports — the runtime loader's script.*
    """
    def __init__(self, data):
        if not isinstance(data, (bytes, bytearray)):
            raise BinaryError("data must be bytes")
        if len(data) < 64:
            raise BinaryError("File too small for PE")
        dos_sig = struct.unpack_from("<H", data, 0)[0]
        if dos_sig != IMAGE_DOS_SIGNATURE:
            raise BinaryError("Not a PE file (bad MZ signature)")
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if e_lfanew + 4 > len(data):
            raise BinaryError("Invalid e_lfanew offset")
        nt_sig = struct.unpack_from("<I", data, e_lfanew)[0]
        if nt_sig != IMAGE_NT_SIGNATURE:
            raise BinaryError("Invalid PE signature")
        self.data = bytes(data)
        self.e_lfanew = e_lfanew
        self._parse_headers()
        self._parse_sections()
        self._parse_imports()
        self._parse_exports()

def _parse_headers(self):
        base = self.e_lfanew + 4
        (self.machine, self.num_sections, self.timestamp, self.symtab_ptr,
         self.num_syms, self.opt_hdr_size, self.characteristics) = \
            struct.unpack_from("<HHIIIHH", self.data, base)
        
        opt_base = base + 20
        if self.opt_hdr_size < 2:
            self.is64 = False
            self.entry_rva = 0
            self.image_base = 0
            self.data_dirs = []
            return
        
        magic = struct.unpack_from("<H", self.data, opt_base)[0]
        self.is64 = (magic == 0x20B)
        
        if self.is64:
            if self.opt_hdr_size < 112:
                self.entry_rva = 0
                self.image_base = 0
                self.data_dirs = []
                return
            (_, _, _, self.entry_rva, _, self.image_base) = \
                struct.unpack_from("<HBBIIQ", self.data, opt_base)
            dd_off = opt_base + 112
        else:
            if self.opt_hdr_size < 96:
                self.entry_rva = 0
                self.image_base = 0
                self.data_dirs = []
                return
            (_, _, _, self.entry_rva, _, self.image_base) = \
                struct.unpack_from("<HBBIIII", self.data, opt_base)
            dd_off = opt_base + 96
        
        num_dd = min(16, (opt_base + self.opt_hdr_size - dd_off) // 8)
        self.data_dirs = []
        for i in range(num_dd):
            rva, sz = struct.unpack_from("<II", self.data, dd_off + i*8)
            self.data_dirs.append((rva, sz))

def _parse_sections(self):
        self.sections = []
        sec_off = self.e_lfanew + 24 + self.opt_hdr_size
        for i in range(self.num_sections):
            off = sec_off + i * 40
            if off + 40 > len(self.data):
                break
            name_raw = self.data[off:off+8]
            name = name_raw.split(b"\x00")[0].decode("utf-8", "replace")
            (vsize, rva, rawsize, rawptr, reloc_ptr, line_ptr, nreloc, nline, flags) = \
                struct.unpack_from("<IIIIIIHHI", self.data, off+8)
            self.sections.append(dict(
                name=name, rva=rva, vsize=vsize, rawptr=rawptr,
                rawsize=rawsize, flags=flags))

def _parse_imports(self):
        """Parse import directory for DLLs and function names; calculate imphash."""
        self.imports = {}
        self.imphash = ""
        if len(self.data_dirs) < 2:
            return
        imp_rva, imp_sz = self.data_dirs[IMAGE_DIRECTORY_ENTRY_IMPORT]
        if not imp_rva or not imp_sz:
            return
        imp_off = self.rva_to_offset(imp_rva)
        if imp_off is None:
            return
        
        # Collect all imports for imphash: DLL.function (ordinal if no name)
        all_imports = []
        
        i = 0
        while True:
            desc_off = imp_off + i * 20
            if desc_off + 20 > len(self.data):
                break
            (ilt_rva, _, _, name_rva, iat_rva) = struct.unpack_from("<IIIII", self.data, desc_off)
            if not ilt_rva and not name_rva:
                break
            dll_off = self.rva_to_offset(name_rva)
            if dll_off is None:
                i += 1
                continue
            dll_name = _cstr(self.data, dll_off).lower()
            
            funcs = []
            thunk_rva = ilt_rva if ilt_rva else iat_rva
            thunk_off = self.rva_to_offset(thunk_rva)
            if thunk_off is None:
                i += 1
                continue
            j = 0
            while True:
                entry_off = thunk_off + j * (8 if self.is64 else 4)
                if entry_off + (8 if self.is64 else 4) > len(self.data):
                    break
                entry = struct.unpack_from("<Q" if self.is64 else "<I", self.data, entry_off)[0]
                if entry == 0:
                    break
                if entry & (1 << (63 if self.is64 else 31)):
                    # import by ordinal
                    ordinal = entry & 0xFFFF
                    funcs.append(f"ord{ordinal}")
                    all_imports.append(f"{dll_name}.ord{ordinal}")
                else:
                    hint_off = self.rva_to_offset(entry)
                    if hint_off is not None and hint_off + 2 < len(self.data):
                        fn = _cstr(self.data, hint_off + 2)
                        funcs.append(fn)
                        all_imports.append(f"{dll_name}.{fn.lower()}")
                j += 1
            self.imports[dll_name] = funcs
            i += 1
        
        # Calculate imphash: MD5 of sorted "dll.function" strings joined by ','
        if all_imports:
            imp_str = ",".join(sorted(set(all_imports)))
            self.imphash = hashlib.md5(imp_str.encode("utf-8")).hexdigest()

def _parse_exports(self):
        """Parse export directory for exported function names."""
        self.exports = []
        if len(self.data_dirs) < 1:
            return
        exp_rva, exp_sz = self.data_dirs[IMAGE_DIRECTORY_ENTRY_EXPORT]
        if not exp_rva or not exp_sz:
            return
        exp_off = self.rva_to_offset(exp_rva)
        if exp_off is None or exp_off + 40 > len(self.data):
            return
        
        (_, _, _, name_rva, base_ord, num_funcs, num_names,
         addr_rva, name_ptr_rva, ord_rva) = struct.unpack_from("<IIIIIIIIII", self.data, exp_off)
        
        name_off = self.rva_to_offset(name_ptr_rva)
        ord_off = self.rva_to_offset(ord_rva)
        if name_off is None or ord_off is None:
            return
        
        for i in range(min(num_names, 10000)):
            if name_off + i*4 + 4 > len(self.data):
                break
            fn_rva = struct.unpack_from("<I", self.data, name_off + i*4)[0]
            fn_off = self.rva_to_offset(fn_rva)
            if fn_off is None:
                continue
            fn = _cstr(self.data, fn_off)
            if fn:
                self.exports.append(fn)

def rva_to_offset(self, rva):
        """Convert RVA to file offset."""
        for sec in self.sections:
            if sec["rva"] <= rva < sec["rva"] + sec["vsize"]:
                delta = rva - sec["rva"]
                if delta < sec["rawsize"]:
                    return sec["rawptr"] + delta
        return None

def get_section(self, name):
        """Fetch section by name."""
        for s in self.sections:
            if s["name"] == name:
                return s
        return None

def read_section_data(self, sec):
        """Read section raw bytes."""
        if sec["rawptr"] + sec["rawsize"] > len(self.data):
            return b""
        return self.data[sec["rawptr"]:sec["rawptr"] + sec["rawsize"]]

def detect_packer(self):
        """Scan for known packer signatures in section names and raw data."""
        # *Packers leave fingerprints — UPX's magic, ASPack's section names, high entropy in .text.*
        hits = []
        for sig, name in PACKER_SIGS.items():
            if sig in self.data:
                hits.append(name)
        for sec in self.sections:
            for sig, name in PACKER_SIGS.items():
                if sig.decode("utf-8", "replace").lower() in sec["name"].lower():
                    if name not in hits:
                        hits.append(name)
        # High entropy check in .text (>7.0 suggests packing/encryption)
        txt = self.get_section(".text")
        if txt:
            code = self.read_section_data(txt)
            if code:
                ent = shannon_entropy(code)
                if ent > 7.0:
                    hits.append(f"High entropy ({ent:.2f}) — likely packed/encrypted")
        return hits

# =========================================================
#  Mach-O parser (UPGRADED: LC_DYSYMTAB, 64-bit fixes)
# =========================================================
class MachOParser:
    """
    *Mach-O is macOS/iOS's format — load commands chain segments, dylibs, and symbol tables into runtime memory.*
    """
    def __init__(self, data):
        if not isinstance(data, (bytes, bytearray)):
            raise BinaryError("data must be bytes")
        if len(data) < 32:
            raise BinaryError("File too small for Mach-O")
        magic = struct.unpack_from("<I", data, 0)[0]
        if magic not in (MH_MAGIC_64, MH_CIGAM_64, MH_MAGIC, MH_CIGAM):
            raise BinaryError("Not a Mach-O file (bad magic)")
        self.data = bytes(data)
        self.is64 = magic in (MH_MAGIC_64, MH_CIGAM_64)
        self.swap = magic in (MH_CIGAM_64, MH_CIGAM)
        self._parse_header()
        self._parse_load_commands()

def _parse_header(self):
        if self.is64:
            (_, self.cputype, self.cpusubtype, self.filetype,
             self.ncmds, self.sizeofcmds, self.flags, _) = \
                struct.unpack_from("<IIIIIIII", self.data, 0)
            self.hdr_size = 32
        else:
            (_, self.cputype, self.cpusubtype, self.filetype,
             self.ncmds, self.sizeofcmds, self.flags) = \
                struct.unpack_from("<IIIIIII", self.data, 0)
            self.hdr_size = 28

def _parse_load_commands(self):
        self.segments = []
        self.symbols = []
        self.dylibs = []
        off = self.hdr_size
        for i in range(self.ncmds):
            if off + 8 > len(self.data):
                break
            cmd, cmdsize = struct.unpack_from("<II", self.data, off)
            if off + cmdsize > len(self.data):
                break
            
            if cmd == LC_SEGMENT_64:
                self._parse_segment_64(off)
            elif cmd == LC_SEGMENT:
                self._parse_segment_32(off)
            elif cmd == LC_SYMTAB:
                self._parse_symtab(off)
            elif cmd == 0xC:  # LC_LOAD_DYLIB
                self._parse_dylib(off, cmdsize)
            
            off += cmdsize

def _parse_segment_64(self, off):
        if off + 72 > len(self.data):
            return
        segname = self.data[off+8:off+24].split(b"\x00")[0].decode("utf-8", "replace")
        (vmaddr, vmsize, fileoff, filesize, maxprot, initprot, nsects, flags) = \
            struct.unpack_from("<QQQQIIII", self.data, off+24)
        self.segments.append(dict(
            name=segname, vmaddr=vmaddr, vmsize=vmsize,
            fileoff=fileoff, filesize=filesize, nsects=nsects))

def _parse_segment_32(self, off):
        if off + 56 > len(self.data):
            return
        segname = self.data[off+8:off+24].split(b"\x00")[0].decode("utf-8", "replace")
        (vmaddr, vmsize, fileoff, filesize, maxprot, initprot, nsects, flags) = \
            struct.unpack_from("<IIIIIIII", self.data, off+24)
        self.segments.append(dict(
            name=segname, vmaddr=vmaddr, vmsize=vmsize,
            fileoff=fileoff, filesize=filesize, nsects=nsects))

def _parse_symtab(self, off):
        if off + 24 > len(self.data):
            return
        (_, _, symoff, nsyms, stroff, strsize) = struct.unpack_from("<IIIIII", self.data, off)
        if symoff + nsyms * (16 if self.is64 else 12) > len(self.data):
            return
        if stroff + strsize > len(self.data):
            return
        strtab = self.data[stroff:stroff+strsize]
        
        for i in range(min(nsyms, 50000)):
            s_off = symoff + i * (16 if self.is64 else 12)
            if self.is64:
                (n_strx, n_type, n_sect, n_desc, n_value) = \
                    struct.unpack_from("<IBBHQ", self.data, s_off)
            else:
                (n_strx, n_type, n_sect, n_desc, n_value) = \
                    struct.unpack_from("<IBBHI", self.data, s_off)
            name = _cstr(strtab, n_strx)
            if name:
                self.symbols.append(dict(name=name, value=n_value, type=n_type))

def _parse_dylib(self, off, cmdsize):
        if off + 24 > len(self.data):
            return
        name_off = struct.unpack_from("<I", self.data, off+8)[0]
        if off + name_off < len(self.data):
            dylib_name = _cstr(self.data, off + name_off)
            if dylib_name:
                self.dylibs.append(dylib_name)

# =========================================================
#  DEX parser (UPGRADED: full Dalvik opcode decode)
# =========================================================
class DexParser:
    """
    *DEX is Android's bytecode — classes, methods, strings, all compressed into a single file for Dalvik/ART.*
    """
    def __init__(self, data):
        if not isinstance(data, (bytes, bytearray)):
            raise BinaryError("data must be bytes")
        if len(data) < 112 or data[:4] != DEX_MAGIC:
            raise BinaryError("Not a DEX file (bad magic)")
        self.data = bytes(data)
        self._parse_header()
        self._parse_strings()
        self._parse_types()
        self._parse_methods()

def _parse_header(self):
        (self.checksum, self.signature,
         self.file_size, self.header_size, self.endian_tag,
         self.link_size, self.link_off,
         self.map_off,
         self.string_ids_size, self.string_ids_off,
         self.type_ids_size, self.type_ids_off,
         self.proto_ids_size, self.proto_ids_off,
         self.field_ids_size, self.field_ids_off,
         self.method_ids_size, self.method_ids_off,
         self.class_defs_size, self.class_defs_off,
         self.data_size, self.data_off) = \
            struct.unpack_from("<I20sIIIIIIIIIIIIIIIIIIII", self.data, 8)

def _parse_strings(self):
        self.strings = []
        for i in range(min(self.string_ids_size, 100000)):
            off_ptr = self.string_ids_off + i * 4
            if off_ptr + 4 > len(self.data):
                break
            str_off = struct.unpack_from("<I", self.data, off_ptr)[0]
            if str_off >= len(self.data):
                continue
            # DEX strings are MUTF-8 with uleb128 length prefix
            size, consumed = decode_uleb128(self.data, str_off)
            start = str_off + consumed
            if start + size > len(self.data):
                continue
            s = self.data[start:start+size].decode("utf-8", "replace")
            self.strings.append(s)

def _parse_types(self):
        self.types = []
        for i in range(min(self.type_ids_size, 100000)):
            off = self.type_ids_off + i * 4
            if off + 4 > len(self.data):
                break
            desc_idx = struct.unpack_from("<I", self.data, off)[0]
            if desc_idx < len(self.strings):
                self.types.append(self.strings[desc_idx])

def _parse_methods(self):
        self.methods = []
        for i in range(min(self.method_ids_size, 100000)):
            off = self.method_ids_off + i * 8
            if off + 8 > len(self.data):
                break
            (class_idx, proto_idx, name_idx) = struct.unpack_from("<HHI", self.data, off)
            if name_idx < len(self.strings):
                self.methods.append(self.strings[name_idx])

def disasm_method(self, code_off, limit=128):
        """Disassemble Dalvik bytecode at code_off."""
        # *Dalvik instructions are variable-width, packed tight — each opcode is a state machine step.*
        if code_off + 16 > len(self.data):
            return []
        (registers_size, ins_size, outs_size, tries_size, debug_info_off, insns_size) = \
            struct.unpack_from("<HHHIII", self.data, code_off)
        code_start = code_off + 16
        code = self.data[code_start:code_start + insns_size*2]
        return disasm_dalvik(code, 0, limit)

# =========================================================
#  WASM parser (basic sections)
# =========================================================
class WasmParser:
    """
    *WASM is WebAssembly — a stack machine for the browser, sections define types, funcs, code, exports.*
    """
    def __init__(self, data):
        if not isinstance(data, (bytes, bytearray)):
            raise BinaryError("data must be bytes")
        if len(data) < 8 or data[:4] != WASM_MAGIC:
            raise BinaryError("Not a WASM file (bad magic)")
        self.data = bytes(data)
        version = struct.unpack_from("<I", data, 4)[0]
        self.version = version
        self._parse_sections()

def _parse_sections(self):
        self.sections = []
        off = 8
        while off < len(self.data):
            if off + 1 > len(self.data):
                break
            sec_id = self.data[off]
            off += 1
            size, consumed = decode_uleb128(self.data, off)
            off += consumed
            if off + size > len(self.data):
                break
            self.sections.append((sec_id, self.data[off:off+size]))
            off += size

# =========================================================
#  .NET assembly parser (UPGRADED: metadata streams)
# =========================================================
class DotNetParser:
    """
    *.NET assemblies are PE with CLI metadata — tables of TypeDef, MethodDef, strings, blobs.*
    """
    def __init__(self, data):
        if not isinstance(data, (bytes, bytearray)):
            raise BinaryError("data must be bytes")
        self.data = bytes(data)
        # Parse as PE first
        try:
            self.pe = PeParser(data)
        except:
            raise BinaryError("Not a valid PE for .NET assembly")
        # CLI header is in data directory 14 (COM descriptor)
        if len(self.pe.data_dirs) < 15:
            raise BinaryError("No CLI metadata directory")
        cli_rva, cli_sz = self.pe.data_dirs[14]
        if not cli_rva:
            raise BinaryError("No CLI header RVA")
        cli_off = self.pe.rva_to_offset(cli_rva)
        if cli_off is None or cli_off + 72 > len(data):
            raise BinaryError("Invalid CLI header offset")
        (cb, major, minor, metadata_rva, metadata_sz) = \
            struct.unpack_from("<IHHII", data, cli_off)
        self.metadata_rva = metadata_rva
        self.metadata_sz = metadata_sz
        self._parse_metadata()

def _parse_metadata(self):
        md_off = self.pe.rva_to_offset(self.metadata_rva)
        if md_off is None or md_off + 16 > len(self.data):
            self.streams = {}
            return
        sig = struct.unpack_from("<I", self.data, md_off)[0]
        if sig != DOTNET_METADATA_SIGNATURE:
            self.streams = {}
            return
        # Skip version string
        ver_len = struct.unpack_from("<I", self.data, md_off+12)[0]
        stream_off = md_off + 16 + ((ver_len + 3) & ~3)
        if stream_off + 4 > len(self.data):
            self.streams = {}
            return
        # Parse streams
        num_streams = struct.unpack_from("<H", self.data, stream_off+2)[0]
        self.streams = {}
        ptr = stream_off + 4
        for i in range(num_streams):
            if ptr + 8 > len(self.data):
                break
            (offset, size) = struct.unpack_from("<II", self.data, ptr)
            ptr += 8
            name_end = self.data.find(b"\x00", ptr)
            if name_end < 0:
                break
            name = self.data[ptr:name_end].decode("utf-8", "replace")
            ptr = (name_end + 4) & ~3
            self.streams[name] = (md_off + offset, size)

# =========================================================
#  Java class file parser (UPGRADED: full constant pool)
# =========================================================
class JavaClassParser:
    """
    *Java .class files are the JVM's input — constant pool, methods, attributes, all spec'd by the JVM book.*
    """
    def __init__(self, data):
        if not isinstance(data, (bytes, bytearray)):
            raise BinaryError("data must be bytes")
        if len(data) < 10 or data[:4] != b"\xCA\xFE\xBA\xBE":
            raise BinaryError("Not a Java class file (bad magic)")
        self.data = bytes(data)
        (self.minor, self.major) = struct.unpack_from(">HH", data, 4)
        self.cp_count = struct.unpack_from(">H", data, 8)[0]
        self._parse_constant_pool()

def _parse_constant_pool(self):
        # *The constant pool is the class's dictionary — strings, class names, method refs all indexed here.*
        self.cp = [None]  # 1-indexed
        off = 10
        i = 1
        while i < self.cp_count:
            if off >= len(self.data):
                break
            tag = self.data[off]
            off += 1
            if tag == 1:  # CONSTANT_Utf8
                length = struct.unpack_from(">H", self.data, off)[0]
                off += 2
                s = self.data[off:off+length].decode("utf-8", "replace")
                off += length
                self.cp.append(("Utf8", s))
            elif tag == 3:  # CONSTANT_Integer
                val = struct.unpack_from(">I", self.data, off)[0]
                off += 4
                self.cp.append(("Integer", val))
            elif tag == 4:  # CONSTANT_Float
                val = struct.unpack_from(">f", self.data, off)[0]
                off += 4
                self.cp.append(("Float", val))
            elif tag == 5:  # CONSTANT_Long
                val = struct.unpack_from(">Q", self.data, off)[0]
                off += 8
                self.cp.append(("Long", val))
                i += 1  # takes two slots
            elif tag == 6:  # CONSTANT_Double
                val = struct.unpack_from(">d", self.data, off)[0]
                off += 8
                self.cp.append(("Double", val))
                i += 1
            elif tag == 7:  # CONSTANT_Class
                name_idx = struct.unpack_from(">H", self.data, off)[0]
                off += 2
                self.cp.append(("Class", name_idx))
            elif tag == 8:  # CONSTANT_String
                string_idx = struct.unpack_from(">H", self.data, off)[0]
                off += 2
                self.cp.append(("String", string_idx))
            elif tag in (9, 10, 11):  # Fieldref, Methodref, InterfaceMethodref
                (class_idx, nat_idx) = struct.unpack_from(">HH", self.data, off)
                off += 4
                self.cp.append((["", "", "", "", "", "", "", "", "", "Fieldref", "Methodref", "InterfaceMethodref"][tag], class_idx, nat_idx))
            elif tag == 12:  # CONSTANT_NameAndType
                (name_idx, desc_idx) = struct.unpack_from(">HH", self.data, off)
                off += 4
                self.cp.append(("NameAndType", name_idx, desc_idx))
            elif tag == 15:  # CONSTANT_MethodHandle
                (ref_kind, ref_idx) = struct.unpack_from(">BH", self.data, off)
                off += 3
                self.cp.append(("MethodHandle", ref_kind, ref_idx))
            elif tag == 16:  # CONSTANT_MethodType
                desc_idx = struct.unpack_from(">H", self.data, off)[0]
                off += 2
                self.cp.append(("MethodType", desc_idx))
            elif tag == 18:  # CONSTANT_InvokeDynamic
                (bootstrap_idx, nat_idx) = struct.unpack_from(">HH", self.data, off)
                off += 4
                self.cp.append(("InvokeDynamic", bootstrap_idx, nat_idx))
            else:
                # Unknown tag; break to avoid corruption
                break
            i += 1

# =========================================================
#  Lua bytecode parser (basic header)
# =========================================================
class LuaBytecodeParser:
    """
    *Lua bytecode is the script's compiled form — header, functions, constants, opcodes.*
    """
    def __init__(self, data):
        if not isinstance(data, (bytes, bytearray)):
            raise BinaryError("data must be bytes")
        if len(data) < 12 or data[:4] != b"\x1BLua":
            raise BinaryError("Not Lua bytecode (bad signature)")
        self.data = bytes(data)
        self.version = data[4]
        self.format = data[5]

# =========================================================
#  Python bytecode parser (.pyc)
# =========================================================
class PycParser:
    """
    *Python .pyc files are marshalled code objects — magic, timestamp, bytecode stream.*
    """
    def __init__(self, data):
        if not isinstance(data, (bytes, bytearray)):
            raise BinaryError("data must be bytes")
        if len(data) < 16:
            raise BinaryError("File too small for .pyc")
        self.data = bytes(data)
        self.magic = struct.unpack_from("<H", data, 0)[0]
        # Python 3.7+ has 16-byte header; 3.6 and earlier 8 or 12
        if len(data) >= 16:
            self.timestamp = struct.unpack_from("<I", data, 8)[0]
        else:
            self.timestamp = 0

# =========================================================
#  Disassemblers
# =========================================================

def disasm_aarch64(code, addr, limit=256):
    """AArch64 disassembler — full A64 instruction set."""
    # *AArch64 is a fixed-width 32-bit instruction set — every word is a self-contained operation.*
    insns = []
    for i in range(0, min(len(code) & ~3, limit*4), 4):
        w = struct.unpack_from("<I", code, i)[0]
        mnem, ops = decode_aarch64_insn(w, addr + i)
        insns.append((addr + i, mnem, ops))
    return insns

def decode_aarch64_insn(w, addr):
    """Decode single AArch64 instruction; returns (mnemonic, operands_str)."""
    # Branch instructions
    if (w & 0xFC000000) == 0x14000000:
        off = _sx(w & 0x3FFFFFF, 26) << 2
        return "b", f"0x{addr + off:x}"
    if (w & 0xFF000010) == 0x54000000:
        off = _sx((w >> 5) & 0x7FFFF, 19) << 2
        cond = ["eq","ne","cs","cc","mi","pl","vs","vc",
                "hi","ls","ge","lt","gt","le","al","nv"][w & 0xF]
        return f"b.{cond}", f"0x{addr + off:x}"
    if (w & 0xFC000000) == 0x94000000:
        off = _sx(w & 0x3FFFFFF, 26) << 2
        return "bl", f"0x{addr + off:x}"
    if (w & 0xFFFFFC1F) == 0xD63F0000:
        rn = (w >> 5) & 0x1F
        return "blr", f"x{rn}"
    if (w & 0xFFFFFC1F) == 0xD61F0000:
        rn = (w >> 5) & 0x1F
        return "br", f"x{rn}"
    if w == 0xD65F03C0:
        return "ret", ""
    if w == 0xD4200000:
        return "brk", "#0"
    if w == 0xD4000001:
        return "svc", "#0"
    
    # Data processing immediate
    if (w & 0x1F000000) == 0x11000000:
        sf = (w >> 31) & 1
        op = (w >> 30) & 1
        S  = (w >> 29) & 1
        sh = (w >> 22) & 1
        imm12 = (w >> 10) & 0xFFF
        rn = (w >> 5) & 0x1F
        rd = w & 0x1F
        shift_amt =
