#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
decoder_batch.py -- Multi-format batch decoder for Pydroid 3
=============================================================
Supports: ELF32/64, PE32/32+, Mach-O, DEX, WASM, Lua bytecode, Python bytecode,
          Java class files, .NET assemblies, COFF, packed binaries, shellcode emulation,
          CFG generation, ROP gadget harvesting, crypto constant detection, IOC extraction,
          anti-debug heuristics, dynamic string decryption, taint analysis, diff engine.

No arguments:
    python decoder_batch.py
    -> scans the folder of this script for *.so, *.apk, *.dex, *.wasm, *.luac, *.pyc, *.class, *.dll, *.exe
    -> decodes every one
    -> writes  result/<name>.<ext>.txt

Single-file CLI:
    python decoder_batch.py file.so [--symbols|--exports|--strings|--text|--func NAME|--emulate|--rop|--diff old.so|--patch OFFSET:HEXBYTES]
"""

import sys, os, struct, glob, time, re, hashlib, base64
from collections import defaultdict

# =========================================================
#  Try to import Unicorn for shellcode emulation
# =========================================================
try:
    from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_ARCH_X86, UC_MODE_64
    from unicorn.arm64_const import *
    from unicorn.x86_const import *
    UNICORN_AVAILABLE = True
except ImportError:
    UNICORN_AVAILABLE = False

# =========================================================
#  ELF constants
# =========================================================
SHT_SYMTAB, SHT_STRTAB, SHT_RELA = 2, 3, 4
SHT_NOBITS, SHT_DYNSYM           = 8, 11
SHF_EXECINSTR                    = 0x4
PT_LOAD                          = 1
EM_AARCH64                       = 183
EM_ARM                           = 40
EM_X86_64                        = 62
EM_386                           = 3
EM_MIPS                          = 8

# =========================================================
#  PE constants
# =========================================================
IMAGE_DOS_SIGNATURE    = 0x5A4D  # MZ
IMAGE_NT_SIGNATURE     = 0x00004550  # PE\0\0
IMAGE_FILE_MACHINE_I386   = 0x014c
IMAGE_FILE_MACHINE_AMD64  = 0x8664
IMAGE_FILE_MACHINE_ARM64  = 0xAA64

# =========================================================
#  Mach-O constants
# =========================================================
MH_MAGIC_64 = 0xFEEDFACF
MH_CIGAM_64 = 0xCFFAEDFE
MH_MAGIC    = 0xFEEDFACE
MH_CIGAM    = 0xCEFAEDFE

# =========================================================
#  DEX constants
# =========================================================
DEX_MAGIC = b"dex\n"

# =========================================================
#  WASM constants
# =========================================================
WASM_MAGIC = b"\x00asm"

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

class BinaryError(Exception):
    pass

# =========================================================
#  ELF64/32 parser
# =========================================================
class ElfParser:
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
        if self.e_shstrndx < len(self.sections):
            sh = self.sections[self.e_shstrndx]
            blob = self.data[sh["offset"]:sh["offset"] + sh["size"]]
            for s in self.sections:
                s["name"] = self._cstr(blob, s["name_off"])

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
            strblob = self.data[strs["offset"]:strs["offset"] + strs["size"]]
            if self.is64:
                entsz = sec["entsize"] or 24
                count = sec["size"] // entsz
                base = sec["offset"]
                for j in range(count):
                    off = base + j * entsz
                    if off + 24 > len(self.data):
                        break
                    (name_off, info, other, shndx, value, size) = \
                        struct.unpack_from("<IBBHQQ", self.data, off)
                    name = self._cstr(strblob, name_off)
                    if not name:
                        continue
                    self.symbols.append(dict(
                        name=name, value=value, size=size,
                        info=info, shndx=shndx,
                        global_=bool(info & 0x10),
                        func=(info & 0xF) == 2))
            else:
                entsz = sec["entsize"] or 16
                count = sec["size"] // entsz
                base = sec["offset"]
                for j in range(count):
                    off = base + j * entsz
                    if off + 16 > len(self.data):
                        break
                    (name_off, value, size, info, other, shndx) = \
                        struct.unpack_from("<IIIBBH", self.data, off)
                    name = self._cstr(strblob, name_off)
                    if not name:
                        continue
                    self.symbols.append(dict(
                        name=name, value=value, size=size,
                        info=info, shndx=shndx,
                        global_=bool(info & 0x10),
                        func=(info & 0xF) == 2))

@staticmethod
    def _cstr(blob, off):
        if off < 0 or off >= len(blob):
            return ""
        end = blob.find(b"\x00", off)
        if end < 0:
            end = len(blob)
        return blob[off:end].decode("utf-8", "replace")

def vaddr_to_offset(self, vaddr):
        for seg in self.segments:
            if seg["type"] == PT_LOAD and \
                    seg["vaddr"] <= vaddr < seg["vaddr"] + seg["filesz"]:
                return seg["offset"] + (vaddr - seg["vaddr"])
        for sec in self.sections:
            if sec["type"] != SHT_NOBITS and \
                    sec["addr"] <= vaddr < sec["addr"] + sec["size"]:
                return sec["offset"] + (vaddr - sec["addr"])
        return None

def section(self, name):
        for s in self.sections:
            if s["name"] == name and s["type"] != SHT_NOBITS:
                return s
        return None

def exec_sections(self):
        return [s for s in self.sections
                if (s["flags"] & SHF_EXECINSTR) and s["type"] != SHT_NOBITS]

def find_symbol(self, name):
        for s in self.symbols:
            if s["name"] == name:
                return s
        return None

def symbol_at(self, vaddr):
        best = None
        for s in self.symbols:
            if not s["func"] or not s["size"]:
                continue
            if s["value"] <= vaddr < s["value"] + s["size"]:
                if best is None or s["value"] > best["value"]:
                    best = s
        return best

# =========================================================
#  PE32/PE32+ parser
# =========================================================
class PEParser:
    def __init__(self, data):
        if len(data) < 64:
            raise BinaryError("File too small for PE")
        dos_magic = struct.unpack_from("<H", data, 0)[0]
        if dos_magic != IMAGE_DOS_SIGNATURE:
            raise BinaryError("Not a PE file (bad DOS magic)")
        e_lfanew = struct.unpack_from("<I", data, 60)[0]
        if e_lfanew + 4 > len(data):
            raise BinaryError("Invalid PE offset")
        nt_sig = struct.unpack_from("<I", data, e_lfanew)[0]
        if nt_sig != IMAGE_NT_SIGNATURE:
            raise BinaryError("Invalid PE signature")
        self.data = bytes(data)
        self.pe_offset = e_lfanew
        self._parse_coff()
        self._parse_optional()
        self._parse_sections()
        self._parse_exports()
        self._parse_imports()

def _parse_coff(self):
        off = self.pe_offset + 4
        (self.machine, self.num_sections, self.timestamp,
         self.symtab_ptr, self.num_syms, self.opthdr_size,
         self.characteristics) = struct.unpack_from("<HHIIIHH", self.data, off)
        self.is64 = (self.machine == IMAGE_FILE_MACHINE_AMD64 or self.machine == IMAGE_FILE_MACHINE_ARM64)

def _parse_optional(self):
        off = self.pe_offset + 24
        if self.opthdr_size < 2:
            self.entry = 0
            self.image_base = 0
            self.data_dirs = []
            return
        magic = struct.unpack_from("<H", self.data, off)[0]
        if magic == 0x20b:  # PE32+
            self.is64 = True
            (_, _, _, _, _, _, self.entry, base_of_code,
             self.image_base) = struct.unpack_from("<HHIIIIIQ", self.data, off)
            dd_off = off + 112
        else:  # PE32
            self.is64 = False
            (_, _, _, _, _, _, self.entry, base_of_code,
             base_of_data, self.image_base) = struct.unpack_from("<HHIIIIIIII", self.data, off)
            dd_off = off + 96
        num_dd = 16
        self.data_dirs = []
        for i in range(num_dd):
            if dd_off + 8 > len(self.data):
                break
            (rva, sz) = struct.unpack_from("<II", self.data, dd_off)
            self.data_dirs.append((rva, sz))
            dd_off += 8

def _parse_sections(self):
        self.sections = []
        sec_off = self.pe_offset + 24 + self.opthdr_size
        for i in range(self.num_sections):
            off = sec_off + i * 40
            if off + 40 > len(self.data):
                break
            name_b = self.data[off:off+8].rstrip(b"\x00")
            (vsize, vaddr, raw_size, raw_ptr,
             reloc_ptr, line_ptr, num_reloc, num_line,
             chars) = struct.unpack_from("<IIIIIIHHI", self.data, off+8)
            self.sections.append(dict(
                name=name_b.decode("utf-8", "replace"),
                vaddr=vaddr, vsize=vsize,
                raw_ptr=raw_ptr, raw_size=raw_size,
                characteristics=chars))

def _parse_exports(self):
        self.exports = []
        if len(self.data_dirs) < 1:
            return
        (exp_rva, exp_sz) = self.data_dirs[0]
        if not exp_rva or not exp_sz:
            return
        exp_off = self.rva_to_offset(exp_rva)
        if exp_off is None or exp_off + 40 > len(self.data):
            return
        (_, _, _, name_rva, base, num_funcs, num_names,
         addr_rva, name_rva_rva, ord_rva) = struct.unpack_from("<IIIIIIIIII", self.data, exp_off)
        addr_off = self.rva_to_offset(addr_rva)
        name_off = self.rva_to_offset(name_rva_rva)
        ord_off = self.rva_to_offset(ord_rva)
        if addr_off is None or name_off is None or ord_off is None:
            return
        for i in range(num_names):
            if name_off + (i+1)*4 > len(self.data):
                break
            n_rva = struct.unpack_from("<I", self.data, name_off + i*4)[0]
            n_str_off = self.rva_to_offset(n_rva)
            if n_str_off is None:
                continue
            name = self._cstr(self.data, n_str_off)
            if ord_off + (i+1)*2 > len(self.data):
                break
            ordinal = struct.unpack_from("<H", self.data, ord_off + i*2)[0]
            if addr_off + (ordinal+1)*4 > len(self.data):
                continue
            func_rva = struct.unpack_from("<I", self.data, addr_off + ordinal*4)[0]
            self.exports.append((name, func_rva))

def _parse_imports(self):
        self.imports = []
        if len(self.data_dirs) < 2:
            return
        (imp_rva, imp_sz) = self.data_dirs[1]
        if not imp_rva or not imp_sz:
            return
        imp_off = self.rva_to_offset(imp_rva)
        if imp_off is None:
            return
        while True:
            if imp_off + 20 > len(self.data):
                break
            (ilt_rva, _, _, name_rva, iat_rva) = struct.unpack_from("<IIIII", self.data, imp_off)
            if not name_rva:
                break
            dll_off = self.rva_to_offset(name_rva)
            if dll_off is None:
                break
            dll = self._cstr(self.data, dll_off)
            thunk_off = self.rva_to_offset(ilt_rva)
            if thunk_off is None:
                imp_off += 20
                continue
            while True:
                if self.is64:
                    if thunk_off + 8 > len(self.data):
                        break
                    val = struct.unpack_from("<Q", self.data, thunk_off)[0]
                    thunk_off += 8
                else:
                    if thunk_off + 4 > len(self.data):
                        break
                    val = struct.unpack_from("<I", self.data, thunk_off)[0]
                    thunk_off += 4
                if not val:
                    break
                if val & (0x8000000000000000 if self.is64 else 0x80000000):
                    # ordinal import
                    ord_num = val & 0xFFFF
                    self.imports.append((dll, f"ord_{ord_num}"))
                else:
                    hint_off = self.rva_to_offset(val)
                    if hint_off is None or hint_off + 2 > len(self.data):
                        continue
                    func_name = self._cstr(self.data, hint_off + 2)
                    self.imports.append((dll, func_name))
            imp_off += 20

def rva_to_offset(self, rva):
        for sec in self.sections:
            if sec["vaddr"] <= rva < sec["vaddr"] + sec["vsize"]:
                return sec["raw_ptr"] + (rva - sec["vaddr"])
        return None

@staticmethod
    def _cstr(blob, off):
        if off < 0 or off >= len(blob):
            return ""
        end = blob.find(b"\x00", off)
        if end < 0:
            end = len(blob)
        return blob[off:end].decode("utf-8", "replace")

# =========================================================
#  Mach-O parser
# =========================================================
class MachOParser:
    def __init__(self, data):
        if len(data) < 32:
            raise BinaryError("File too small for Mach-O")
        magic = struct.unpack_from("<I", data, 0)[0]
        if magic not in (MH_MAGIC_64, MH_CIGAM_64, MH_MAGIC, MH_CIGAM):
            raise BinaryError("Not a Mach-O file")
        self.data = bytes(data)
        self.is64 = (magic in (MH_MAGIC_64, MH_CIGAM_64))
        self.is_le = (magic in (MH_MAGIC_64, MH_MAGIC))
        self._parse_header()
        self._parse_load_commands()

def _parse_header(self):
        if self.is64:
            (self.magic, self.cputype, self.cpusubtype, self.filetype,
             self.ncmds, self.sizeofcmds, self.flags, _) = struct.unpack_from("<IIIIIIII", self.data, 0)
            self.lc_offset = 32
        else:
            (self.magic, self.cputype, self.cpusubtype, self.filetype,
             self.ncmds, self.sizeofcmds, self.flags) = struct.unpack_from("<IIIIIII", self.data, 0)
            self.lc_offset = 28

def _parse_load_commands(self):
        self.segments = []
        self.symbols = []
        off = self.lc_offset
        for _ in range(self.ncmds):
            if off + 8 > len(self.data):
                break
            (cmd, cmdsize) = struct.unpack_from("<II", self.data, off)
            if cmd in (0x19, 0x1):  # LC_SEGMENT_64, LC_SEGMENT
                if self.is64:
                    (_, _, segname_b, vmaddr, vmsize, fileoff, filesize,
                     maxprot, initprot, nsects, flags) = struct.unpack_from("<II16sQQQQIIII", self.data, off)
                else:
                    (_, _, segname_b, vmaddr, vmsize, fileoff, filesize,
                     maxprot, initprot, nsects, flags) = struct.unpack_from("<II16sIIIIIIII", self.data, off)
                segname = segname_b.rstrip(b"\x00").decode("utf-8", "replace")
                self.segments.append(dict(name=segname, vmaddr=vmaddr, vmsize=vmsize,
                                          fileoff=fileoff, filesize=filesize))
            off += cmdsize

# =========================================================
#  DEX parser
# =========================================================
class DEXParser:
    def __init__(self, data):
        if len(data) < 112 or data[:4] != DEX_MAGIC:
            raise BinaryError("Not a DEX file")
        self.data = bytes(data)
        (self.version, self.checksum, self.signature,
         self.file_size, self.header_size, self.endian_tag,
         self.link_size, self.link_off,
         self.map_off, self.string_ids_size, self.string_ids_off,
         self.type_ids_size, self.type_ids_off,
         self.proto_ids_size, self.proto_ids_off,
         self.field_ids_size, self.field_ids_off,
         self.method_ids_size, self.method_ids_off,
         self.class_defs_size, self.class_defs_off,
         self.data_size, self.data_off) = struct.unpack_from("<4sI20sIIIIIIIIIIIIIIIIIIII", data, 0)
        self.strings = []
        self.types = []
        self.methods = []
        self._parse_strings()
        self._parse_types()
        self._parse_methods()

def _parse_strings(self):
        for i in range(self.string_ids_size):
            off = self.string_ids_off + i * 4
            if off + 4 > len(self.data):
                break
            str_off = struct.unpack_from("<I", self.data, off)[0]
            if str_off >= len(self.data):
                continue
            # MUTF-8 length prefix (uleb128)
            length, pos = self._read_uleb128(str_off)
            s = self.data[pos:pos+length].decode("utf-8", "replace")
            self.strings.append(s)

def _parse_types(self):
        for i in range(self.type_ids_size):
            off = self.type_ids_off + i * 4
            if off + 4 > len(self.data):
                break
            desc_idx = struct.unpack_from("<I", self.data, off)[0]
            if desc_idx < len(self.strings):
                self.types.append(self.strings[desc_idx])

def _parse_methods(self):
        for i in range(self.method_ids_size):
            off = self.method_ids_off + i * 8
            if off + 8 > len(self.data):
                break
            (class_idx, proto_idx, name_idx) = struct.unpack_from("<HHI", self.data, off)
            if name_idx < len(self.strings):
                self.methods.append(self.strings[name_idx])

def _read_uleb128(self, off):
        result = 0
        shift = 0
        pos = off
        while True:
            if pos >= len(self.data):
                break
            b = self.data[pos]
            pos += 1
            result |= (b & 0x7F) << shift
            if (b & 0x80) == 0:
                break
            shift += 7
        return result, pos

# =========================================================
#  WASM parser
# =========================================================
class WASMParser:
    def __init__(self, data):
        if len(data) < 8 or data[:4] != WASM_MAGIC:
            raise BinaryError("Not a WASM file")
        self.data = bytes(data)
        self.version = struct.unpack_from("<I", data, 4)[0]
        self.functions = []
        self.imports = []
        self.exports = []
        self._parse_sections()

def _parse_sections(self):
        pos = 8
        while pos < len(self.data):
            if pos + 1 > len(self.data):
                break
            sec_id = self.data[pos]
            pos += 1
            sec_len, pos = self._read_uleb128(pos)
            sec_end = pos + sec_len
            if sec_id == 2:  # Import section
                count, pos = self._read_uleb128(pos)
                for _ in range(count):
                    mod_len, pos = self._read_uleb128(pos)
                    mod = self.data[pos:pos+mod_len].decode("utf-8", "replace")
                    pos += mod_len
                    field_len, pos = self._read_uleb128(pos)
                    field = self.data[pos:pos+field_len].decode("utf-8", "replace")
                    pos += field_len
                    kind = self.data[pos] if pos < len(self.data) else 0
                    pos += 1
                    # skip type index/table/mem/global descriptor
                    if kind == 0:  # func
                        _, pos = self._read_uleb128(pos)
                    elif kind == 1:  # table
                        pos += 1; _, pos = self._read_uleb128(pos); _, pos = self._read_uleb128(pos)
                    elif kind == 2:  # mem
                        pos += 1; _, pos = self._read_uleb128(pos)
                    elif kind == 3:  # global
                        pos += 1; pos += 1
                    self.imports.append((mod, field, kind))
            elif sec_id == 7:  # Export section
                count, pos = self._read_uleb128(pos)
                for _ in range(count):
                    field_len, pos = self._read_uleb128(pos)
                    field = self.data[pos:pos+field_len].decode("utf-8", "replace")
                    pos += field_len
                    kind = self.data[pos] if pos < len(self.data) else 0
                    pos += 1
                    idx, pos = self._read_uleb128(pos)
                    self.exports.append((field, kind, idx))
            pos = sec_end

def _read_uleb128(self, off):
        result = 0
        shift = 0
        pos = off
        while pos < len(self.data):
            b = self.data[pos]
            pos += 1
            result |= (b & 0x7F) << shift
            if (b & 0x80) == 0:
                break
            shift += 7
        return result, pos

# =========================================================
#  ARM64 fallback decoder
# =========================================================
COND  = ["eq","ne","cs","cc","mi","pl","vs","vc",
         "hi","ls","ge","lt","gt","le","al","nv"]
SHIFT = ["lsl","lsr","asr","ror"]

def _sx(v, bits):
    m = 1 << (bits - 1)
    v &= (1 << bits) - 1
    return (v ^ m) - m

def _ror(v, r, w):
    r %= w
    if r == 0:
        return v
    m = (1 << w) - 1
    return ((v >> r) | (v << (w - r))) & m

def _reg(n, is64, sp=False):
    if n == 31:
        return ("sp" if is64 else "wsp") if sp else ("xzr" if is64 else "wzr")
    return ("x%d" if is64 else "w%d") % n

def _bitmask_imm(N, imms, immr, is64):
    if not is64 and N:
        return None
    combined = (N << 6) | ((~imms) & 0x3F)
    if combined == 0:
        return None
    length = combined.bit_length() - 1
    if length < 1:
        return None
    esize = 1 << length
    if not is64 and esize > 32:
        return None
    levels = esize - 1
    S = imms & levels
    R = immr & levels
    if S == levels:
        return None
    welem = (1 << (S + 1)) - 1
    wmask = _ror(welem, R, esize)
    out, rem = 0, (64 if is64 else 32)
    while rem > 0:
        out = (out << esize) | wmask
        rem -= esize
    return out

class ARM64Decoder:
    def decode(self, w, addr=0):
        sf = (w >> 31) & 1
        is64 = bool(sf)

if w == 0xD503201F: return "nop", ""
        if w == 0xD65F03C0: return "ret", ""
        if w == 0xD503233F: return "paciasp", ""
        if w == 0xD50323BF: return "autiasp", ""

if (w & 0xFFFFFC1F) == 0xD65F0000:
            rn = (w >> 5) & 0x1F
            return "ret", ("" if rn == 30 else _reg(rn, True, True))
        if (w & 0xFFFFFC1F) == 0xD61F0000:
            return "br",  _reg((w >> 5) & 0x1F, True, True)
        if (w & 0xFFFFFC1F) == 0xD63F0000:
            return "blr", _reg((w >> 5) & 0x1F, True, True)

if (w & 0x7C000000) == 0x14000000:
            op = (w >> 31) & 1
            off = _sx(w & 0x03FFFFFF, 26) << 2
            return ("bl" if op else "b"), "0x%x" % (addr + off)
        if (w & 0xFF000010) == 0x54000000:
            off = _sx((w >> 5) & 0x7FFFF, 19) << 2
            return "b." + COND[w & 0xF], "0x%x" % (addr + off)
        if (w & 0x7E000000) == 0x34000000:
            op = (w >> 24) & 1
            off = _sx((w >> 5) & 0x7FFFF, 19) << 2
            rt = w & 0x1F
            return ("cbnz" if op else "cbz"), \
                   "%s, 0x%x" % (_reg(rt, is64), addr + off)
        if (w & 0x7E000000) == 0x36000000:
            op = (w >> 24) & 1
            bit = (((w >> 31) & 1) << 5) | ((w >> 19) & 0x1F)
            off = _sx((w >> 5) & 0x3FFF, 14) << 2
            rt = w & 0x1F
            return ("tbnz" if op else "tbz"), \
                   "%s, #%d, 0x%x" % (_reg(rt, is64), bit, addr + off)

if (w & 0x1F000000) == 0x10000000:
            op = (w >> 31) & 1
            immlo = (w >> 29) & 0x3
            immhi = (w >> 5) & 0x7FFFF
            imm = _sx((immhi << 2) | immlo, 21)
            rd = w & 0x1F
            if op:
                return "adrp", "%s, 0x%x" % (_reg(rd, True, True),
                                              (addr & ~0xFFF) + (imm << 12))
            return "adr", "%s, 0x%x" % (_reg(rd, True, True), addr + imm)

if (w & 0x1F800000) == 0x11000000:
            op, S = (w >> 30) & 1, (w >> 29) & 1
            sh = (w >> 22) & 1
            imm = (w >> 10) & 0xFFF
            if sh: imm <<= 12
            rn, rd = (w >> 5) & 0x1F, w & 0x1F
            if S and rd == 31:
                return ("cmp" if op else "cmn"), \
                       "%s, #0x%x" % (_reg(rn, is64, True), imm)
            if S:
                return ("subs" if op else "adds"), \
                       "%s, %s, #0x%x" % (_reg(rd, is64),
                                          _reg(rn, is64, True), imm)
            return ("sub" if op else "add"), \
                   "%s, %s, #0x%x" % (_reg(rd, is64, True),
                                      _reg(rn, is64, True), imm)

if (w & 0x1F200000) == 0x0B000000:
            op, S = (w >> 30) & 1, (w >> 29) & 1
            shift = (w >> 22) & 3
            rm = (w >> 16) & 0x1F
            amt = (w >> 10) & 0x3F
            rn, rd = (w >> 5) & 0x1F, w & 0x1F
            if shift == 3:
                return "???", "0x%08x" % w
            ops = "%s, %s" % (_reg(rn, is64), _reg(rm, is64))
            if amt: ops += ", %s #%d" % (SHIFT[shift], amt)
            if S and rd == 31:
                return ("cmp" if op else "cmn"), ops
            if S:
                return ("subs" if op else "adds"), \
                       "%s, %s" % (_reg(rd, is64), ops)
            return ("sub" if op else "add"), \
                   "%s, %s" % (_reg(rd, is64, True), ops)

if (w & 0x1F800000) == 0x12000000:
            opc = (w >> 29) & 3
            N = (w >> 22) & 1
            immr = (w >> 16) & 0x3F
            imms = (w >> 10) & 0x3F
            rn, rd = (w >> 5) & 0x1F, w & 0x1F
            imm = _bitmask_imm(N, imms, immr, is64)
            if imm is None:
                return "???", "0x%08x" % w
            names = ["and", "orr", "eor", "ands"]
            if opc == 1 and rn == 31:
                return "mov", "%s, #0x%x" % (_reg(rd, is64, True), imm)
            if opc == 3 and rd == 31:
                return "tst", "%s, #0x%x" % (_reg(rn, is64, True), imm)
            return names[opc], "%s, %s, #0x%x" % (
                _reg(rd, is64, True), _reg(rn, is64), imm)

if (w & 0x1F000000) == 0x0A000000:
            opc = (w >> 29) & 3
            N   = (w >> 21) & 1
            shift = (w >> 22) & 3
            rm = (w >> 16) & 0x1F
            amt = (w >> 10) & 0x3F
            rn, rd = (w >> 5) & 0x1F, w & 0x1F
            if shift == 3:
                return "???", "0x%08x" % w
            base = ["and", "orr", "eor", "ands"][opc]
            if N:
                base = {"and": "bic", "orr": "orn",
                        "eor": "eon", "ands": "bics"}[base]
            ops = "%s, %s" % (_reg(rn, is64), _reg(rm, is64))
            if amt: ops += ", %s #%d" % (SHIFT[shift], amt)
            if opc == 1 and N == 0 and rn == 31:
                s2 = _reg(rm, is64)
                if amt: s2 += ", %s #%d" % (SHIFT[shift], amt)
                return "mov", "%s, %s" % (_reg(rd, is64, True), s2)
            if opc == 3 and N == 0 and rd == 31:
                return "tst", ops
            return base, "%s, %s" % (_reg(rd, is64), ops)

if (w & 0x1F800000) == 0x12800000:
            opc = (w >> 29) & 3
            hw  = (w >> 21) & 3
            imm = (w >> 5) & 0xFFFF
            rd  = w & 0x1F
            names = {0: "movn", 2: "movz", 3: "movk"}
            mnem = names.get(opc, "???")
            sh = hw * 16
            if sh:
                return mnem, "%s, #0x%x, lsl #%d" % (
                    _reg(rd, is64, True), imm, sh)
            return mnem, "%s, #0x%x" % (_reg(rd, is64, True), imm)

if (w & 0x1F800000) == 0x13000000:
            opc = (w >> 29) & 3
            immr = (w >> 16) & 0x3F
            imms = (w >> 10) & 0x3F
            rn, rd = (w >> 5) & 0x1F, w & 0x1F
            mnem = ["sbfm", "bfm", "ubfm", "???"][opc]
            return mnem, "%s, %s, #%d, #%d" % (
                _reg(rd, is64), _reg(rn, is64), immr, imms)

if (w & 0x1F000000) == 0x1B000000:
            op = (w >> 15) & 1
            rm, ra = (w >> 16) & 0x1F, (w >> 10) & 0x1F
            rn, rd = (w >> 5) & 0x1F, w & 0x1F
            if op:
                return "msub", "%s, %s, %s, %s" % (
                    _reg(rd, is64), _reg(rn, is64),
                    _reg(rm, is64), _reg(ra, is64))
            if ra == 31:
                return "mul", "%s, %s, %s" % (
                    _reg(rd, is64), _reg(rn, is64), _reg(rm, is64))
            return "madd", "%s, %s, %s, %s" % (
                _reg(rd, is64), _reg(rn, is64),
                _reg(rm, is64), _reg(ra, is64))

if (w & 0x1FE0FC00) == 0x1AC00C00:
            op = (w >> 10) & 1
            rm, rn, rd = (w >> 16) & 0x1F, (w >> 5) & 0x1F, w & 0x1F
            return ("sdiv" if op else "udiv"), "%s, %s, %s" % (
                _reg(rd, is64), _reg(rn, is64), _reg(rm, is64))

if (w & 0x1FE00C00) == 0x1A800000:
            op, S = (w >> 30) & 1, (w >> 29) & 1
            rm, cond = (w >> 16) & 0x1F, (w >> 12) & 0xF
            rn, rd = (w >> 5) & 0x1F, w & 0x1F
            mnem = {(0, 0): "csel", (0, 1): "csinc",
                    (1, 0): "csinv", (1, 1): "csneg"}[(op, S)]
            return mnem, "%s, %s, %s, %s" % (
                _reg(rd, is64), _reg(rn, is64),
                _reg(rm, is64), COND[cond])

if (w & 0x3B000000) == 0x39000000:
            size = (w >> 30) & 3
            V    = (w >> 26) & 1
            opc  = (w >> 22) & 3
            imm  = ((w >> 10) & 0xFFF) << size
            rn, rt = (w >> 5) & 0x1F, w & 0x1F
            if V:
                vn = "s%d" % rt if size == 2 else "d%d" % rt
                return ("ldr" if opc == 1 else "str"), \
                       "%s, [%s, #0x%x]" % (vn, _reg(rn, True, True), imm)
            if opc == 0:
                mnem = ["strb", "strh", "str", "str"][size]
            elif opc == 1:
                mnem = ["ldrb", "ldrh", "ldr", "ldr"][size]
            elif opc == 2:
                mnem = ["ldrsb", "ldrsh", "ldrsw", "???"][size]
            else:
                mnem = "prfm"
            return mnem, "%s, [%s, #0x%x]" % (
                _reg(rt, size == 3), _reg(rn, True, True), imm)

if (w & 0x3B000000) == 0x38000000:
            size = (w >> 30) & 3
            V    = (w >> 26) & 1
            opc  = (w >> 22) & 3
            op2  = (w >> 10) & 3
            imm9 = _sx((w >> 12) & 0x1FF, 9)
            rn, rt = (w >> 5) & 0x1F, w & 0x1F
            if V:
                return "???", "0x%08x" % w
            if op2 == 0:
                if opc == 0:
                    mnem = ["sturb", "sturh", "stur", "stur"][size]
                elif opc == 1:
                    mnem = ["ldurb", "ldurh", "ldur", "ldur"][size]
                elif opc == 2:
                    mnem = ["ldursb", "ldursh", "ldursw", "???"][size]
                else:
                    mnem = "prfum"
                return mnem, "%s, [%s, #%d]" % (
                    _reg(rt, size == 3), _reg(rn, True, True), imm9)
            if opc == 0:
                mnem = ["strb", "strh", "str", "str"][size]
            elif opc == 1:
                mnem = ["ldrb", "ldrh", "ldr", "ldr"][size]
            else:
                mnem = "ldrsw" if opc == 2 and size == 2 else "???"
            if op2 == 1:
                return mnem, "%s, [%s], #%d" % (
                    _reg(rt, size == 3), _reg(rn, True, True), imm9)
            if op2 == 3:
                return mnem, "%s, [%s, #%d]!" % (
                    _reg(rt, size == 3), _reg(rn, True, True), imm9)
            return "???", "0x%08x" % w

if (w & 0x3B000000) == 0x18000000:
            opc = (w >> 30) & 3
            off = _sx((w >> 5) & 0x7FFFF, 19) << 2
            rt  = w & 0x1F
            tgt = "0x%x" % (addr + off)
            if opc == 0: return "ldr",   "%s, %s" % (_reg(rt, False), tgt)
            if opc == 1: return "ldr",   "%s, %s" % (_reg(rt, True),  tgt)
            if opc == 2: return "ldrsw", "%s, %s" % (_reg(rt, True),  tgt)
            return "prfm", "#%d, %s" % (rt, tgt)

ldp_stp = {
            0xA9000000: ("stp", True,  "off"),  0xA9800000: ("stp", True,  "pre"),
            0xA8800000: ("stp", True,  "post"), 0xA9400000: ("ldp", True,  "off"),
            0xA9C00000: ("ldp", True,  "pre"),  0xA8C00000: ("ldp", True,  "post"),
            0x29000000: ("stp", False, "off"),  0x29800000: ("stp", False, "pre"),
            0x28800000: ("stp", False, "post"), 0x29400000: ("ldp", False, "off"),
            0x29C00000: ("ldp", False, "pre"),  0x28C00000: ("ldp", False, "post"),
        }
        key = w & 0xFFC00000
        if key in ldp_stp:
            mnem, is64b, mode = ldp_stp[key]
            imm7 = _sx((w >> 15) & 0x7F, 7) << (3 if is64b else 2)
            rt2 = (w >> 10) & 0x1F
            rn  = (w >> 5) & 0x1F
            rt  = w & 0x1F
            if mode == "off":
                return mnem, "%s, %s, [%s, #%d]" % (
                    _reg(rt, is64b), _reg(rt2, is64b),
                    _reg(rn, True, True), imm7)
            if mode == "pre":
                return mnem, "%s, %s, [%s, #%d]!" % (
                    _reg(rt, is64b), _reg(rt2, is64b),
                    _reg(rn, True, True), imm7)
            return mnem, "%s, %s, [%s], #%d" % (
                _reg(rt, is64b), _reg(rt2, is64b),
                _reg(rn, True, True), imm7)

if (w & 0xFFF00000) == 0xD5300000:
            return "mrs", "0x%08x" % w
        if (w & 0xFFF00000) == 0xD5100000:
            return "msr", "0x%08x" % w
        if (w & 0xFFFFF01F) == 0xD503201F:
            return "hint", "#0x%x" % ((w >> 5) & 0x7F)

return "???", "0x%08x" % w

# =========================================================
#  String extraction
# =========================================================
def extract_strings(data, min_len=4):
    """
    Extract ASCII/UTF-8 strings; returns list of (offset, string).
    *The binary's telling its story — strings are breadcrumbs to intent.*
    """
    results = []
    current = []
    start = 0
    for i, b in enumerate(data):
        if 32 <= b < 127 or b in (9, 10, 13):
            if not current:
                start = i
            current.append(b)
        else:
            if len(current) >= min_len:
                results.append((start, bytes(current).decode("utf-8", "replace")))
            current = []
    if len(current) >= min_len:
        results.append((start, bytes(current).decode("utf-8", "replace")))
    return results

# =========================================================
#  Crypto constant detection
# =========================================================
def find_crypto_constants(data):
    """
    Scan for AES S-box, SHA-256 K constants, common RSA exponents.
    *Crypto doesn't hide — it announces itself in magic tables.*
    """
    hits = []
    # AES S-box
    if AES_SBOX in data:
        off = data.find(AES_SBOX)
        hits.append(("AES-128 S-box (Rijndael forward)", off))
    # SHA-256 K
    for i, k in enumerate(SHA256_K[:8]):
        needle = struct.pack("<I", k)
        if needle in data:
            off = data.find(needle)
            hits.append((f"SHA-256 K[{i}] = 0x{k:08x}", off))
            break
    # RSA exponent 65537
    needle = struct.pack("<I", 65537)
    if needle in data:
        off = data.find(needle)
        hits.append(("RSA public exponent 65537", off))
    return hits

# =========================================================
#  Network IOC extraction
# =========================================================
def extract_iocs(data):
    """
    Regex sweep for IPs, domains, URLs.
    *C2 domains whisper from the .rodata section; URLs scream from error strings.*
    """
    s = data.decode("utf-8", "replace")
    ipv4 = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', s)
    urls = re.findall(r'https?://[^\s<>"{}|\\^`\[\]]+', s)
    domains = re.findall(r'\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b', s)
    return {"ipv4": list(set(ipv4)), "urls": list(set(urls)), "domains": list(set(domains[:50]))}

# =========================================================
#  Anti-debug/anti-VM heuristics
# =========================================================
def detect_anti_debug(data):
    """
    Scan for ptrace, timing checks, QEMU artifacts, /proc/self/status reads.
    *The paranoid binary sniffs for gdb, frida, QEMU — every check is a tell.*
    """
    hits = []
    # ptrace string
    if b"ptrace" in data:
        hits.append("ptrace() reference (anti-debug)")
    if b"/proc/self/status" in data:
        hits.append("/proc/self/status read (TracerPid check)")
    if b"QEMU" in data or b"qemu" in data:
        hits.append("QEMU artifact (anti-VM)")
    if b"frida" in data or b"Frida" in data:
        hits.append("Frida detection string")
    return hits

# =========================================================
#  ROP gadget harvester
# =========================================================
def harvest_rop_gadgets(data, base_addr=0, arch="arm64", max_gadgets=100):
    """
    Scan executable bytes for ROP gadgets ending in ret/br/blr.
    *Every `ret` is a pivot
