(function (root) {
'use strict';

const MH_MAGIC      = 0xFEEDFACE;
const MH_CIGAM      = 0xCEFAEDFE;
const MH_MAGIC_64   = 0xFEEDFACF;
const MH_CIGAM_64   = 0xCFFAEDFE;
const FAT_MAGIC     = 0xCAFEBABE;
const FAT_CIGAM     = 0xBEBAFECA;
const FAT_MAGIC_64  = 0xCAFEBABF;
const FAT_CIGAM_64  = 0xBFBAFECA;

const MH_NOUNDEFS              = 0x1;
const MH_PIE                   = 0x200000;
const MH_NO_HEAP_EXECUTION     = 0x1000000;
const MH_ALLOW_STACK_EXECUTION = 0x20000;
const MH_HAS_TLV_DESCRIPTORS   = 0x800000;
const MH_DYLDLINK              = 0x4;
const MH_TWOLEVEL              = 0x80;
const MH_WEAK_DEFINES          = 0x8000;

const LC_REQ_DYLD = 0x80000000;
const LC = {
    SEGMENT:             0x01,
    SYMTAB:              0x02,
    THREAD:              0x04,
    UNIXTHREAD:          0x05,
    DYSYMTAB:            0x0B,
    LOAD_DYLIB:          0x0C,
    ID_DYLIB:            0x0D,
    LOAD_DYLINKER:       0x0E,
    ID_DYLINKER:         0x0F,
    ROUTINES:            0x11,
    SUB_FRAMEWORK:       0x12,
    SUB_UMBRELLA:        0x13,
    SUB_CLIENT:          0x14,
    SUB_LIBRARY:         0x15,
    TWOLEVEL_HINTS:      0x16,
    LOAD_WEAK_DYLIB:     0x18 | LC_REQ_DYLD,
    SEGMENT_64:          0x19,
    ROUTINES_64:         0x1A,
    UUID:                0x1B,
    RPATH:               0x1C | LC_REQ_DYLD,
    CODE_SIGNATURE:      0x1D,
    SEGMENT_SPLIT_INFO:  0x1E,
    REEXPORT_DYLIB:      0x1F | LC_REQ_DYLD,
    LAZY_LOAD_DYLIB:     0x20,
    ENCRYPTION_INFO:     0x21,
    DYLD_INFO:           0x22,
    DYLD_INFO_ONLY:      0x22 | LC_REQ_DYLD,
    LOAD_UPWARD_DYLIB:   0x23 | LC_REQ_DYLD,
    VERSION_MIN_MACOSX:  0x24,
    VERSION_MIN_IPHONEOS:0x25,
    FUNCTION_STARTS:     0x26,
    DYLD_ENVIRONMENT:    0x27,
    MAIN:                0x28 | LC_REQ_DYLD,
    DATA_IN_CODE:        0x29,
    SOURCE_VERSION:      0x2A,
    DYLIB_CODE_SIGN_DRS: 0x2B,
    ENCRYPTION_INFO_64:  0x2C,
    LINKER_OPTION:       0x2D,
    LINKER_OPTIMIZATION_HINT: 0x2E,
    VERSION_MIN_TVOS:    0x2F,
    VERSION_MIN_WATCHOS: 0x30,
    NOTE:                0x31,
    BUILD_VERSION:       0x32,
    DYLD_EXPORTS_TRIE:   0x33 | LC_REQ_DYLD,
    DYLD_CHAINED_FIXUPS: 0x34 | LC_REQ_DYLD,
    FILESET_ENTRY:       0x35 | LC_REQ_DYLD,
};

const CPU_TYPE = {
    X86:    0x07,
    X86_64: 0x07 | 0x01000000,
    ARM:    0x0C,
    ARM64:  0x0C | 0x01000000,
    ARM64_32: 0x0C | 0x02000000,
    PPC:    0x12,
    PPC64:  0x12 | 0x01000000,
};

const CPU_TYPE_NAMES = {
    [CPU_TYPE.X86]: 'x86',
    [CPU_TYPE.X86_64]: 'x86_64',
    [CPU_TYPE.ARM]: 'arm',
    [CPU_TYPE.ARM64]: 'arm64',
    [CPU_TYPE.ARM64_32]: 'arm64_32',
    [CPU_TYPE.PPC]: 'ppc',
    [CPU_TYPE.PPC64]: 'ppc64',
};

const ARM64_SUBTYPES = { 0: 'all', 1: 'v8', 2: 'e' };
const ARM_SUBTYPES = { 0: 'all', 5: 'v4t', 6: 'v6', 7: 'v5tej', 8: 'xscale', 9: 'v7', 10: 'v7f', 11: 'v7s', 12: 'v7k', 13: 'v8', 14: 'v6m', 15: 'v7m', 16: 'v7em' };

const FILETYPE_NAMES = {
    1: 'object', 2: 'execute', 3: 'fvmlib', 4: 'core', 5: 'preload',
    6: 'dylib', 7: 'dylinker', 8: 'bundle', 9: 'dylib_stub', 10: 'dsym',
    11: 'kext_bundle', 12: 'fileset',
};

const PLATFORM_NAMES = {
    1: 'macOS', 2: 'iOS', 3: 'tvOS', 4: 'watchOS', 5: 'bridgeOS',
    6: 'macCatalyst', 7: 'iOSSimulator', 8: 'tvOSSimulator',
    9: 'watchOSSimulator', 10: 'driverKit', 11: 'visionOS',
    12: 'visionOSSimulator',
};

const CSMAGIC = {
    REQUIREMENT:         0xFADE0C00,
    REQUIREMENTS:        0xFADE0C01,
    CODEDIRECTORY:       0xFADE0C02,
    EMBEDDED_SIGNATURE:  0xFADE0CC0,
    DETACHED_SIGNATURE:  0xFADE0CC1,
    BLOBWRAPPER:         0xFADE0B01,
    EMBEDDED_ENTITLEMENTS: 0xFADE7171,
    EMBEDDED_DER_ENTITLEMENTS: 0xFADE7172,
};

const CS_SLOT = {
    CODEDIRECTORY: 0,
    INFO: 1,
    REQUIREMENTS: 2,
    RESOURCEDIR: 3,
    APPLICATION: 4,
    ENTITLEMENTS: 5,
    REPSPECIFIC: 6,
    DER_ENTITLEMENTS: 7,
    ALTERNATE_CODEDIRECTORIES: 0x1000,
    SIGNATURESLOT: 0x10000,
    IDENTIFICATIONSLOT: 0x10001,
    TICKETSLOT: 0x10002,
};

const CS_HASHTYPE = {
    1: 'SHA1', 2: 'SHA256', 3: 'SHA256_TRUNCATED', 4: 'SHA384', 5: 'SHA512',
};

const CS_EXECSEG = {
    MAIN_BINARY:     0x1,
    ALLOW_UNSIGNED:  0x10,
    DEBUGGER:        0x20,
    JIT:             0x40,
    SKIP_LV:         0x80,
    CAN_LOAD_CDHASH: 0x100,
    CAN_EXEC_CDHASH: 0x200,
};

class Reader {
    constructor(bytes, offset = 0, littleEndian = true) {
        this.bytes = bytes;
        this.start = offset;
        this.pos = offset;
        this.le = littleEndian;
        this.view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    }
    seek(p) { this.pos = p; return this; }
    skip(n) { this.pos += n; return this; }
    u8()  { const v = this.view.getUint8(this.pos); this.pos += 1; return v; }
    u16() { const v = this.view.getUint16(this.pos, this.le); this.pos += 2; return v; }
    u32() { const v = this.view.getUint32(this.pos, this.le); this.pos += 4; return v; }
    u64() {
        const lo = this.view.getUint32(this.pos + (this.le ? 0 : 4), this.le);
        const hi = this.view.getUint32(this.pos + (this.le ? 4 : 0), this.le);
        this.pos += 8;
        return hi * 0x100000000 + lo;
    }
    u16be() { const v = this.view.getUint16(this.pos, false); this.pos += 2; return v; }
    u32be() { const v = this.view.getUint32(this.pos, false); this.pos += 4; return v; }
    u64be() {
        const hi = this.view.getUint32(this.pos, false);
        const lo = this.view.getUint32(this.pos + 4, false);
        this.pos += 8;
        return hi * 0x100000000 + lo;
    }
    cstring(maxLen) {
        let s = '';
        for (let i = 0; i < maxLen; i++) {
            const b = this.bytes[this.pos + i];
            if (b === 0) break;
            if (b >= 32 && b < 127) s += String.fromCharCode(b);
            else s += '\\x' + b.toString(16).padStart(2, '0');
        }
        this.pos += maxLen;
        return s;
    }
    fixedString(len) {
        let s = '';
        for (let i = 0; i < len; i++) {
            const b = this.bytes[this.pos + i];
            if (b === 0) break;
            s += String.fromCharCode(b);
        }
        this.pos += len;
        return s;
    }
    slice(len) {
        const v = this.bytes.subarray(this.pos, this.pos + len);
        this.pos += len;
        return v;
    }
}

function hex(n, width = 8) {
    return '0x' + (n >>> 0).toString(16).padStart(width, '0');
}

function bytesToHex(bytes, max = 64) {
    const n = Math.min(bytes.length, max);
    let s = '';
    for (let i = 0; i < n; i++) s += bytes[i].toString(16).padStart(2, '0');
    if (bytes.length > max) s += '…';
    return s;
}

function decodeUTF8(bytes) {
    try { return new TextDecoder('utf-8').decode(bytes); }
    catch (_) {
        let s = '';
        for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
        return s;
    }
}

function detectMagic(bytes) {
    if (bytes.length < 4) return { kind: 'unknown' };
    const r = new Reader(bytes, 0, false);
    const m = r.u32be();
    if (m === FAT_MAGIC)    return { kind: 'fat', le: false, bits64: false };
    if (m === FAT_CIGAM)    return { kind: 'fat', le: true,  bits64: false };
    if (m === FAT_MAGIC_64) return { kind: 'fat', le: false, bits64: true };
    if (m === FAT_CIGAM_64) return { kind: 'fat', le: true,  bits64: true };
    if (m === MH_MAGIC)     return { kind: 'mach-o', le: false, bits64: false };
    if (m === MH_CIGAM)     return { kind: 'mach-o', le: true,  bits64: false };
    if (m === MH_MAGIC_64)  return { kind: 'mach-o', le: false, bits64: true };
    if (m === MH_CIGAM_64)  return { kind: 'mach-o', le: true,  bits64: true };
    return { kind: 'unknown' };
}

function isMachO(bytes) {
    return detectMagic(bytes).kind !== 'unknown';
}

function readFat(bytes) {
    const det = detectMagic(bytes);
    if (det.kind !== 'fat') return null;
    const r = new Reader(bytes, 4, det.le);
    const nfat = r.u32be();
    const arches = [];
    for (let i = 0; i < nfat && i < 32; i++) {
        const cputype = r.u32be();
        const cpusubtype = r.u32be();
        let offset, size, align;
        if (det.bits64) {
            offset = r.u64be();
            size   = r.u64be();
            align  = r.u32be();
            r.skip(4);
        } else {
            offset = r.u32be();
            size   = r.u32be();
            align  = r.u32be();
        }
        arches.push({
            cputype,
            cpusubtype,
            arch: archName(cputype, cpusubtype),
            offset, size, align,
        });
    }
    return arches;
}

function archName(cputype, cpusubtype) {
    const base = CPU_TYPE_NAMES[cputype];
    if (!base) return 'unknown(0x' + cputype.toString(16) + ')';
    const sub = cpusubtype & 0x00FFFFFF;
    if (cputype === CPU_TYPE.ARM64 && ARM64_SUBTYPES[sub]) {
        return sub === 0 ? 'arm64' : 'arm64' + ARM64_SUBTYPES[sub];
    }
    if (cputype === CPU_TYPE.ARM && ARM_SUBTYPES[sub]) {
        return 'arm' + ARM_SUBTYPES[sub];
    }
    return base;
}

function flagsList(flags) {
    const result = [];
    const map = {
        [MH_NOUNDEFS]:              'NOUNDEFS',
        [MH_DYLDLINK]:              'DYLDLINK',
        [MH_TWOLEVEL]:              'TWOLEVEL',
        [MH_WEAK_DEFINES]:          'WEAK_DEFINES',
        [MH_ALLOW_STACK_EXECUTION]: 'ALLOW_STACK_EXECUTION',
        [MH_HAS_TLV_DESCRIPTORS]:   'HAS_TLV_DESCRIPTORS',
        [MH_PIE]:                   'PIE',
        [MH_NO_HEAP_EXECUTION]:     'NO_HEAP_EXECUTION',
    };
    for (const [bit, name] of Object.entries(map)) {
        if (flags & (+bit)) result.push(name);
    }
    return result;
}

function lcName(cmd) {
    const masked = cmd & ~LC_REQ_DYLD;
    for (const [name, val] of Object.entries(LC)) {
        if ((val & ~LC_REQ_DYLD) === masked) return name;
    }
    return 'UNKNOWN(' + hex(cmd, 4) + ')';
}

function parseThin(bytes, baseOffset, length) {
    const slice = length != null
        ? bytes.subarray(baseOffset, baseOffset + length)
        : bytes.subarray(baseOffset);
    const det = detectMagic(slice);
    if (det.kind !== 'mach-o') return null;

    const r = new Reader(slice, 0, det.le);
    r.u32();
    const cputype     = r.u32();
    const cpusubtype  = r.u32();
    const filetype    = r.u32();
    const ncmds       = r.u32();
    const sizeofcmds  = r.u32();
    const flags       = r.u32();
    if (det.bits64) r.u32();

    const arch = archName(cputype, cpusubtype);
    const header = {
        magic: det.bits64 ? (det.le ? MH_CIGAM_64 : MH_MAGIC_64) : (det.le ? MH_CIGAM : MH_MAGIC),
        bits: det.bits64 ? 64 : 32,
        littleEndian: det.le,
        cputype,
        cpusubtype,
        cpusubtypeCapBits: (cpusubtype >>> 24) & 0xFF,
        arch,
        filetype,
        filetypeName: FILETYPE_NAMES[filetype] || ('unknown(' + filetype + ')'),
        ncmds,
        sizeofcmds,
        flags,
        flagNames: flagsList(flags),
        pie: !!(flags & MH_PIE),
        noHeapExec: !!(flags & MH_NO_HEAP_EXECUTION),
        allowsStackExec: !!(flags & MH_ALLOW_STACK_EXECUTION),
        dyldLink: !!(flags & MH_DYLDLINK),
        twoLevelNS: !!(flags & MH_TWOLEVEL),
    };

    const cmdsStart = det.bits64 ? 32 : 28;
    r.seek(cmdsStart);

    const result = {
        header,
        loadCommands: [],
        segments: [],
        sections: [],
        dylibs: [],
        rpaths: [],
        uuid: null,
        minOS: null,
        sdk: null,
        platform: null,
        sourceVersion: null,
        entryPoint: null,
        encryption: { present: false, encrypted: false, cryptid: 0, cryptOffset: 0, cryptSize: 0 },
        codeSignatureRef: null,
        symtab: null,
        dysymtab: null,
        dyldInfo: null,
        functionStarts: null,
        dataInCode: null,
        linkerOptions: [],
    };

    for (let i = 0; i < ncmds; i++) {
        const cmdPos = r.pos;
        if (cmdPos + 8 > slice.length) break;
        const cmd = r.u32();
        const cmdsize = r.u32();
        if (cmdsize < 8) break;
        const lcInfo = { cmd, cmdName: lcName(cmd), cmdsize, offset: cmdPos };
        result.loadCommands.push(lcInfo);

        const after = cmdPos + cmdsize;
        try {
            switch (cmd & ~LC_REQ_DYLD) {
                case LC.SEGMENT & ~LC_REQ_DYLD:
                case LC.SEGMENT_64 & ~LC_REQ_DYLD: {
                    const is64 = (cmd === LC.SEGMENT_64);
                    const segname = r.fixedString(16);
                    const vmaddr  = is64 ? r.u64() : r.u32();
                    const vmsize  = is64 ? r.u64() : r.u32();
                    const fileoff = is64 ? r.u64() : r.u32();
                    const filesize= is64 ? r.u64() : r.u32();
                    const maxprot = r.u32();
                    const initprot= r.u32();
                    const nsects  = r.u32();
                    const segflags= r.u32();
                    const seg = {
                        segname, vmaddr, vmsize, fileoff, filesize,
                        maxprot, initprot, nsects, flags: segflags,
                        sections: [],
                    };
                    for (let s = 0; s < nsects && s < 256; s++) {
                        const sectname = r.fixedString(16);
                        const secSeg   = r.fixedString(16);
                        const addr     = is64 ? r.u64() : r.u32();
                        const size     = is64 ? r.u64() : r.u32();
                        const offset   = r.u32();
                        const align    = r.u32();
                        const reloff   = r.u32();
                        const nreloc   = r.u32();
                        const sflags   = r.u32();
                        const reserved1= r.u32();
                        const reserved2= r.u32();
                        if (is64) r.u32();
                        const sect = {
                            sectname, segname: secSeg, addr, size,
                            offset, align, reloff, nreloc,
                            flags: sflags, reserved1, reserved2,
                        };
                        seg.sections.push(sect);
                        result.sections.push(sect);
                    }
                    result.segments.push(seg);
                    break;
                }
                case LC.UUID & ~LC_REQ_DYLD: {
                    const u = r.slice(16);
                    const s = [...u].map(b => b.toString(16).padStart(2, '0')).join('');
                    result.uuid = (s.slice(0,8) + '-' + s.slice(8,12) + '-' + s.slice(12,16) + '-' + s.slice(16,20) + '-' + s.slice(20,32)).toUpperCase();
                    break;
                }
                case LC.LOAD_DYLIB & ~LC_REQ_DYLD:
                case LC.LOAD_WEAK_DYLIB & ~LC_REQ_DYLD:
                case LC.REEXPORT_DYLIB & ~LC_REQ_DYLD:
                case LC.LAZY_LOAD_DYLIB & ~LC_REQ_DYLD:
                case LC.LOAD_UPWARD_DYLIB & ~LC_REQ_DYLD:
                case LC.ID_DYLIB & ~LC_REQ_DYLD: {
                    const nameOff = r.u32();
                    const tstamp  = r.u32();
                    const curVer  = r.u32();
                    const compVer = r.u32();
                    const start = cmdPos + nameOff;
                    const end = after;
                    const name = decodeUTF8(slice.subarray(start, end)).split('\0')[0];
                    const entry = {
                        cmd: lcInfo.cmdName,
                        name,
                        timestamp: tstamp,
                        currentVersion: formatVersion(curVer),
                        compatibilityVersion: formatVersion(compVer),
                        weak: (cmd & ~LC_REQ_DYLD) === (LC.LOAD_WEAK_DYLIB & ~LC_REQ_DYLD),
                        reexport: (cmd & ~LC_REQ_DYLD) === (LC.REEXPORT_DYLIB & ~LC_REQ_DYLD),
                    };
                    if ((cmd & ~LC_REQ_DYLD) === (LC.ID_DYLIB & ~LC_REQ_DYLD)) {
                        result.idDylib = entry;
                    } else {
                        result.dylibs.push(entry);
                    }
                    break;
                }
                case LC.RPATH & ~LC_REQ_DYLD: {
                    const pathOff = r.u32();
                    const start = cmdPos + pathOff;
                    const end = after;
                    result.rpaths.push(decodeUTF8(slice.subarray(start, end)).split('\0')[0]);
                    break;
                }
                case LC.VERSION_MIN_IPHONEOS:
                case LC.VERSION_MIN_MACOSX:
                case LC.VERSION_MIN_TVOS:
                case LC.VERSION_MIN_WATCHOS: {
                    const version = r.u32();
                    const sdk = r.u32();
                    result.minOS = formatVersion(version);
                    result.sdk = formatVersion(sdk);
                    if (cmd === LC.VERSION_MIN_IPHONEOS) result.platform = 'iOS';
                    else if (cmd === LC.VERSION_MIN_MACOSX) result.platform = 'macOS';
                    else if (cmd === LC.VERSION_MIN_TVOS) result.platform = 'tvOS';
                    else if (cmd === LC.VERSION_MIN_WATCHOS) result.platform = 'watchOS';
                    break;
                }
                case LC.BUILD_VERSION: {
                    const platform = r.u32();
                    const minos = r.u32();
                    const sdk = r.u32();
                    const ntools = r.u32();
                    result.platform = PLATFORM_NAMES[platform] || ('platform_' + platform);
                    result.minOS = formatVersion(minos);
                    result.sdk = formatVersion(sdk);
                    result.buildTools = [];
                    for (let t = 0; t < ntools && t < 8; t++) {
                        const tool = r.u32();
                        const tver = r.u32();
                        result.buildTools.push({ tool, version: formatVersion(tver) });
                    }
                    break;
                }
                case LC.SOURCE_VERSION: {
                    const v = r.u64();
                    const a = (v >>> 40) & 0xFFFFFF;
                    const b = (v >>> 30) & 0x3FF;
                    const c = (v >>> 20) & 0x3FF;
                    const d = (v >>> 10) & 0x3FF;
                    const e =  v & 0x3FF;
                    result.sourceVersion = [a,b,c,d,e].join('.');
                    break;
                }
                case LC.MAIN & ~LC_REQ_DYLD: {
                    const entryoff = r.u64();
                    const stacksize = r.u64();
                    result.entryPoint = { entryOffset: entryoff, stackSize: stacksize };
                    break;
                }
                case LC.ENCRYPTION_INFO:
                case LC.ENCRYPTION_INFO_64: {
                    const cryptoff = r.u32();
                    const cryptsize = r.u32();
                    const cryptid = r.u32();
                    if ((cmd & ~LC_REQ_DYLD) === LC.ENCRYPTION_INFO_64) r.u32();
                    result.encryption = {
                        present: true,
                        encrypted: cryptid !== 0,
                        cryptid,
                        cryptOffset: cryptoff,
                        cryptSize: cryptsize,
                    };
                    break;
                }
                case LC.CODE_SIGNATURE & ~LC_REQ_DYLD: {
                    const dataoff = r.u32();
                    const datasize = r.u32();
                    result.codeSignatureRef = { offset: dataoff, size: datasize };
                    break;
                }
                case LC.SYMTAB: {
                    const symoff = r.u32();
                    const nsyms = r.u32();
                    const stroff = r.u32();
                    const strsize = r.u32();
                    result.symtab = { symoff, nsyms, stroff, strsize };
                    break;
                }
                case LC.DYSYMTAB: {
                    const obj = {};
                    obj.ilocalsym = r.u32(); obj.nlocalsym = r.u32();
                    obj.iextdefsym = r.u32(); obj.nextdefsym = r.u32();
                    obj.iundefsym = r.u32(); obj.nundefsym = r.u32();
                    obj.tocoff = r.u32(); obj.ntoc = r.u32();
                    obj.modtaboff = r.u32(); obj.nmodtab = r.u32();
                    obj.extrefsymoff = r.u32(); obj.nextrefsyms = r.u32();
                    obj.indirectsymoff = r.u32(); obj.nindirectsyms = r.u32();
                    obj.extreloff = r.u32(); obj.nextrel = r.u32();
                    obj.locreloff = r.u32(); obj.nlocrel = r.u32();
                    result.dysymtab = obj;
                    break;
                }
                case LC.DYLD_INFO & ~LC_REQ_DYLD:
                case LC.DYLD_INFO_ONLY & ~LC_REQ_DYLD: {
                    const obj = {};
                    obj.rebase_off = r.u32(); obj.rebase_size = r.u32();
                    obj.bind_off = r.u32();   obj.bind_size = r.u32();
                    obj.weak_bind_off = r.u32(); obj.weak_bind_size = r.u32();
                    obj.lazy_bind_off = r.u32(); obj.lazy_bind_size = r.u32();
                    obj.export_off = r.u32(); obj.export_size = r.u32();
                    result.dyldInfo = obj;
                    break;
                }
                case LC.FUNCTION_STARTS:
                case LC.DATA_IN_CODE:
                case LC.DYLIB_CODE_SIGN_DRS:
                case LC.SEGMENT_SPLIT_INFO:
                case LC.LINKER_OPTIMIZATION_HINT:
                case LC.DYLD_EXPORTS_TRIE & ~LC_REQ_DYLD:
                case LC.DYLD_CHAINED_FIXUPS & ~LC_REQ_DYLD: {
                    const dataoff = r.u32();
                    const datasize = r.u32();
                    const key = lcInfo.cmdName.toLowerCase().replace(/^lc_/, '');
                    result[key] = { offset: dataoff, size: datasize };
                    break;
                }
                case LC.LINKER_OPTION: {
                    const count = r.u32();
                    const start = r.pos;
                    const slice2 = slice.subarray(start, after);
                    const parts = decodeUTF8(slice2).split('\0').filter(Boolean).slice(0, count);
                    result.linkerOptions.push(parts);
                    break;
                }
            }
        } catch (e) { }

        r.seek(after);
    }

    result.symbolTable = parseSymtab(slice, result);
    result.checksec = computeChecksec(slice, result);

    if (result.codeSignatureRef) {
        result.codeSignature = parseCodeSignature(slice, result.codeSignatureRef);
    }

    return result;
}

function formatVersion(v) {
    if (v === 0) return null;
    const major = (v >>> 16) & 0xFFFF;
    const minor = (v >>> 8) & 0xFF;
    const patch = v & 0xFF;
    return major + '.' + minor + (patch ? '.' + patch : '');
}

function parseSymtab(bytes, info) {
    if (!info.symtab) return null;
    const { symoff, nsyms, stroff, strsize } = info.symtab;
    if (symoff + (nsyms * (info.header.bits === 64 ? 16 : 12)) > bytes.length) return null;
    if (stroff + strsize > bytes.length) return null;

    const is64 = info.header.bits === 64;
    const le = info.header.littleEndian;
    const entrySize = is64 ? 16 : 12;
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);

    const strtab = bytes.subarray(stroff, stroff + strsize);
    const symbols = [];
    const externalNames = new Set();
    const importedSymbols = new Set();
    let truncated = false;

    const max = Math.min(nsyms, 100000);
    for (let i = 0; i < max; i++) {
        const off = symoff + i * entrySize;
        const strx = view.getUint32(off, le);
        const type = view.getUint8(off + 4);
        const sect = view.getUint8(off + 5);
        const desc = view.getUint16(off + 6, le);
        const value = is64 ? readU64(view, off + 8, le) : view.getUint32(off + 8, le);

        let name = '';
        if (strx < strsize) {
            let end = strx;
            while (end < strsize && strtab[end] !== 0 && end - strx < 1024) end++;
            name = decodeUTF8(strtab.subarray(strx, end));
        }
        const N_TYPE = type & 0x0E;
        const N_EXT  = type & 0x01;
        const N_STAB = type & 0xE0;

        if (!N_STAB) {
            if (N_TYPE === 0x0 && N_EXT && name) importedSymbols.add(name);
            if (N_EXT && name) externalNames.add(name);
        }
        if (symbols.length < 256) symbols.push({ name, type, sect, value });
    }
    if (nsyms > max) truncated = true;

    return {
        count: nsyms,
        truncated,
        sample: symbols,
        imported: [...importedSymbols],
        external: [...externalNames],
    };
}

function readU64(view, offset, le) {
    const lo = view.getUint32(offset + (le ? 0 : 4), le);
    const hi = view.getUint32(offset + (le ? 4 : 0), le);
    return hi * 0x100000000 + lo;
}

function computeChecksec(bytes, info) {
    const flags = info.header.flags;
    const imported = info.symbolTable?.imported || [];

    const hasStackGuard = imported.includes('___stack_chk_guard') || imported.includes('___stack_chk_fail');
    const hasObjcRelease = imported.some(n => n === '_objc_release' || n === '_objc_release_x0' || n === '_objc_release_x1' || n === '_objc_release_x2' || n === '_objc_release_x3');
    const hasSwift = imported.some(n => n.startsWith('_swift_') || n.startsWith('__swift_'));
    const hasSwiftRelease = imported.includes('_swift_release');
    const hasARC = hasObjcRelease || hasSwiftRelease;
    const encryptedFairPlay = info.encryption.present && info.encryption.encrypted;

    return {
        pie:                !!(flags & MH_PIE),
        nx_heap:            !!(flags & MH_NO_HEAP_EXECUTION),
        nx_stack:           !(flags & MH_ALLOW_STACK_EXECUTION),
        stackCanary:        hasStackGuard,
        arc:                hasARC,
        objc:               imported.some(n => n.startsWith('_objc_') || n.startsWith('_OBJC_')),
        swift:              hasSwift,
        encryptedFairPlay,
        twoLevelNamespace:  !!(flags & MH_TWOLEVEL),
        weakDefines:        !!(flags & MH_WEAK_DEFINES),
        rpaths:             info.rpaths.length,
        codeSigned:         !!info.codeSignatureRef,
    };
}

function parseCodeSignature(bytes, ref) {
    const { offset, size } = ref;
    if (offset + size > bytes.length) return { error: 'Code signature out of bounds' };
    const blob = bytes.subarray(offset, offset + size);
    const r = new Reader(blob, 0, false);
    const magic = r.u32be();
    if (magic !== CSMAGIC.EMBEDDED_SIGNATURE && magic !== CSMAGIC.DETACHED_SIGNATURE) {
        return { error: 'Not a SuperBlob (magic=' + hex(magic) + ')' };
    }
    const length = r.u32be();
    const count  = r.u32be();
    const slots = [];
    for (let i = 0; i < count && i < 64; i++) {
        const type   = r.u32be();
        const slotOff = r.u32be();
        slots.push({ type, offset: slotOff, slotName: slotName(type) });
    }

    const result = {
        magic: hex(magic),
        length,
        slotCount: count,
        slots,
        codeDirectory: null,
        alternateCodeDirectories: [],
        entitlements: null,
        derEntitlements: null,
        requirements: null,
        cms: null,
    };

    for (const slot of slots) {
        if (slot.offset >= blob.length) continue;
        const sub = blob.subarray(slot.offset);
        const subR = new Reader(sub, 0, false);
        const m = subR.u32be();
        const l = subR.u32be();
        if (l < 8 || l > sub.length + 4) continue;
        const data = sub.subarray(8, l);

        if (m === CSMAGIC.CODEDIRECTORY) {
            const cd = parseCodeDirectory(sub, l);
            if (slot.type === CS_SLOT.CODEDIRECTORY) result.codeDirectory = cd;
            else result.alternateCodeDirectories.push({ type: slot.type, ...cd });
        } else if (m === CSMAGIC.EMBEDDED_ENTITLEMENTS) {
            result.entitlements = {
                magic: hex(m),
                length: l,
                xml: decodeUTF8(data),
            };
        } else if (m === CSMAGIC.EMBEDDED_DER_ENTITLEMENTS) {
            result.derEntitlements = {
                magic: hex(m),
                length: l,
                hex: bytesToHex(data, 32),
                size: data.length,
            };
        } else if (m === CSMAGIC.REQUIREMENTS) {
            result.requirements = parseRequirements(sub, l);
        } else if (m === CSMAGIC.BLOBWRAPPER) {
            result.cms = {
                magic: hex(m),
                length: l,
                size: data.length,
                hex: bytesToHex(data, 64),
                derPresent: data.length > 0,
            };
        }
    }

    return result;
}

function slotName(type) {
    for (const [k, v] of Object.entries(CS_SLOT)) {
        if (v === type) return k;
    }
    return 'unknown(0x' + type.toString(16) + ')';
}

function parseCodeDirectory(blob, length) {
    const r = new Reader(blob, 0, false);
    const magic = r.u32be();
    const blobLen = r.u32be();
    const version = r.u32be();
    const flags = r.u32be();
    const hashOffset = r.u32be();
    const identOffset = r.u32be();
    const nSpecialSlots = r.u32be();
    const nCodeSlots = r.u32be();
    const codeLimit = r.u32be();
    const hashSize = r.u8();
    const hashType = r.u8();
    const platform = r.u8();
    const pageSize = r.u8();
    const spare2 = r.u32be();

    let scatterOffset = 0, teamOffset = 0, codeLimit64 = null,
        execSegBase = null, execSegLimit = null, execSegFlags = null;
    if (version >= 0x20100) scatterOffset = r.u32be();
    if (version >= 0x20200) teamOffset = r.u32be();
    if (version >= 0x20300) { r.u32be(); codeLimit64 = r.u64be(); }
    if (version >= 0x20400) {
        execSegBase = r.u64be();
        execSegLimit = r.u64be();
        execSegFlags = r.u64be();
    }

    let identifier = '';
    if (identOffset && identOffset < blob.length) {
        const end = Math.min(blob.length, identOffset + 512);
        identifier = decodeUTF8(blob.subarray(identOffset, end)).split('\0')[0];
    }
    let teamId = '';
    if (teamOffset && teamOffset < blob.length) {
        const end = Math.min(blob.length, teamOffset + 64);
        teamId = decodeUTF8(blob.subarray(teamOffset, end)).split('\0')[0];
    }

    let cdHash = null;
    if (hashOffset >= 0 && hashSize > 0 && hashSize < 64) {
        const hashesStart = hashOffset;
        const slot0End = hashesStart + hashSize;
        if (slot0End <= blob.length) {
            const computed = computeCDHash(blob.subarray(0, length), hashType);
            cdHash = computed;
        }
    }

    return {
        magic: hex(magic),
        length: blobLen,
        version: hex(version),
        flags: hex(flags),
        flagNames: cdFlagsList(flags),
        hashOffset,
        identOffset,
        nSpecialSlots,
        nCodeSlots,
        codeLimit,
        codeLimit64,
        hashSize,
        hashType,
        hashAlgorithm: CS_HASHTYPE[hashType] || ('type_' + hashType),
        pageSize: pageSize ? (1 << pageSize) : 0,
        platform,
        teamId,
        identifier,
        execSegBase,
        execSegLimit,
        execSegFlags,
        execSegFlagNames: execSegFlags ? execSegFlagsList(Number(execSegFlags)) : [],
        cdHash,
    };
}

function cdFlagsList(flags) {
    const out = [];
    const map = {
        0x00000001: 'host',
        0x00000002: 'adhoc',
        0x00000004: 'forceHard',
        0x00000010: 'killer',
        0x00000020: 'expires',
        0x00000100: 'restrict',
        0x00000200: 'enforcement',
        0x00000400: 'libraryValidation',
        0x00000800: 'runtime',
        0x00001000: 'linkerSigned',
    };
    for (const [bit, name] of Object.entries(map)) {
        if (flags & (+bit)) out.push(name);
    }
    return out;
}

function execSegFlagsList(flags) {
    const out = [];
    for (const [bit, name] of Object.entries(CS_EXECSEG)) {
        if (flags & bit) out.push(name);
    }
    return out;
}

function computeCDHash(blob, hashType) {
    return null;
}

function parseRequirements(blob, length) {
    return {
        magic: hex(CSMAGIC.REQUIREMENTS),
        length,
        present: true,
    };
}

function parseEntitlements(machoResult) {
    if (!machoResult?.codeSignature?.entitlements?.xml) return null;
    return machoResult.codeSignature.entitlements.xml;
}

function parse(bytes) {
    if (!(bytes instanceof Uint8Array)) {
        bytes = new Uint8Array(bytes);
    }
    const det = detectMagic(bytes);
    if (det.kind === 'unknown') return { error: 'Not a Mach-O or FAT binary', size: bytes.length };
    if (det.kind === 'fat') {
        const arches = readFat(bytes);
        return {
            type: 'fat',
            size: bytes.length,
            arches,
            slices: arches.map(a => parseThin(bytes, a.offset, a.size)),
        };
    }
    const thin = parseThin(bytes, 0, bytes.length);
    return { type: 'thin', size: bytes.length, ...thin };
}

function summarize(result) {
    if (!result) return null;
    if (result.error) return { error: result.error };
    if (result.type === 'fat') {
        const slices = result.slices.map(summarize).filter(Boolean);
        const merged = mergeChecksec(slices);
        return {
            type: 'fat',
            arches: result.arches.map(a => a.arch),
            slices,
            checksec: merged,
        };
    }
    return {
        type: 'thin',
        arch: result.header.arch,
        bits: result.header.bits,
        platform: result.platform,
        minOS: result.minOS,
        sdk: result.sdk,
        sourceVersion: result.sourceVersion,
        filetype: result.header.filetypeName,
        uuid: result.uuid,
        flags: result.header.flagNames,
        dylibs: (result.dylibs || []).map(d => d.name),
        rpaths: result.rpaths,
        segments: (result.segments || []).map(s => ({
            name: s.segname,
            vmaddr: '0x' + s.vmaddr.toString(16),
            vmsize: s.vmsize,
            initprot: s.initprot,
            maxprot: s.maxprot,
            sections: s.sections.map(sec => ({
                name: sec.segname + ',' + sec.sectname,
                size: sec.size,
                offset: sec.offset,
            })),
        })),
        encryption: result.encryption,
        codeSignature: result.codeSignature ? {
            present: true,
            slotCount: result.codeSignature.slotCount,
            codeDirectory: result.codeSignature.codeDirectory,
            entitlementsPresent: !!result.codeSignature.entitlements,
            derEntitlementsPresent: !!result.codeSignature.derEntitlements,
            cmsPresent: !!result.codeSignature.cms,
        } : { present: false },
        entitlementsXml: result.codeSignature?.entitlements?.xml || null,
        checksec: result.checksec,
        symbolCount: result.symbolTable?.count || 0,
        importedCount: result.symbolTable?.imported.length || 0,
    };
}

function mergeChecksec(slices) {
    if (!slices.length) return null;
    const first = slices[0].checksec;
    if (!first) return null;
    const all = {};
    for (const key of Object.keys(first)) {
        if (typeof first[key] === 'boolean') {
            all[key] = slices.every(s => s.checksec && s.checksec[key]);
        } else {
            all[key] = first[key];
        }
    }
    return all;
}

const api = {
    parse,
    parseThin,
    summarize,
    detectMagic,
    isMachO,
    readFat,
    parseEntitlements,
    archName,
    formatVersion,
    LC,
    CSMAGIC,
    CS_SLOT,
};

if (typeof module !== 'undefined' && module.exports) {
    module.exports = api;
} else {
    root.IPAA = root.IPAA || {};
    root.IPAA.MachO = api;
}

})(typeof self !== 'undefined' ? self : this);
