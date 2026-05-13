(function (root) {
'use strict';

class BinaryPlistParser {
    constructor(buffer) {
        if (buffer instanceof ArrayBuffer) {
            this.buffer = new Uint8Array(buffer);
            this.view = new DataView(buffer);
        } else if (buffer instanceof Uint8Array) {
            this.buffer = buffer;
            this.view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);
        } else {
            throw new Error('Invalid buffer');
        }
    }
    parse() {
        let magic = '';
        for (let i = 0; i < 6 && i < this.buffer.length; i++) magic += String.fromCharCode(this.buffer[i]);
        if (!magic.startsWith('bplist')) return null;
        try {
            const trailerOffset = this.buffer.length - 32;
            if (trailerOffset < 8) return null;
            const offsetSize = this.buffer[trailerOffset + 6];
            const objectRefSize = this.buffer[trailerOffset + 7];
            if (offsetSize === 0 || objectRefSize === 0 || offsetSize > 8 || objectRefSize > 8) return null;
            const numObjects = this._uintBE(trailerOffset + 8, 8);
            const topObject  = this._uintBE(trailerOffset + 16, 8);
            const offsetTableOffset = this._uintBE(trailerOffset + 24, 8);
            if (numObjects === 0 || offsetTableOffset >= this.buffer.length) return null;
            this.offsetSize = offsetSize;
            this.objectRefSize = objectRefSize;
            this.offsets = new Array(numObjects);
            for (let i = 0; i < numObjects; i++) {
                this.offsets[i] = this._uintBE(offsetTableOffset + i * offsetSize, offsetSize);
            }
            return this._parseObject(topObject);
        } catch (_) { return null; }
    }
    _uintBE(offset, size) {
        let v = 0;
        for (let i = 0; i < size; i++) v = v * 256 + (this.buffer[offset + i] || 0);
        return v;
    }
    _parseObject(index) {
        if (index >= this.offsets.length) return null;
        const off = this.offsets[index];
        if (off >= this.buffer.length) return null;
        const marker = this.buffer[off];
        const type = marker >> 4;
        const info = marker & 0x0F;
        try {
            switch (type) {
                case 0x0:
                    if (info === 0x00) return null;
                    if (info === 0x08) return false;
                    if (info === 0x09) return true;
                    return null;
                case 0x1: return this._integer(off, info);
                case 0x2: return this._real(off, info);
                case 0x3: return this._date(off);
                case 0x4: return this._data(off, info);
                case 0x5: return this._asciiString(off, info);
                case 0x6: return this._utf16String(off, info);
                case 0x8: return this._uid(off, info);
                case 0xA: return this._array(off, info);
                case 0xC: return this._array(off, info);
                case 0xD: return this._dict(off, info);
            }
        } catch (_) { return null; }
        return null;
    }
    _length(off, info) {
        if (info !== 0x0F) return { length: info, dataOffset: off + 1 };
        const intMarker = this.buffer[off + 1];
        if ((intMarker >> 4) !== 0x1) return { length: 0, dataOffset: off + 2 };
        const intInfo = intMarker & 0x0F;
        const intBytes = 1 << intInfo;
        const length = this._uintBE(off + 2, intBytes);
        return { length, dataOffset: off + 2 + intBytes };
    }
    _integer(off, info) {
        const bytes = 1 << info;
        let v = 0;
        for (let i = 0; i < bytes; i++) v = v * 256 + this.buffer[off + 1 + i];
        if (bytes === 8 && v > 0x7FFFFFFFFFFFFFFF) v -= 0x10000000000000000;
        return v;
    }
    _real(off, info) {
        const bytes = 1 << info;
        if (bytes === 4) return this.view.getFloat32(off + 1, false);
        if (bytes === 8) return this.view.getFloat64(off + 1, false);
        return 0;
    }
    _date(off) {
        const t = this.view.getFloat64(off + 1, false);
        return new Date((t + 978307200) * 1000).toISOString();
    }
    _data(off, info) {
        const { length, dataOffset } = this._length(off, info);
        const slice = this.buffer.slice(dataOffset, dataOffset + length);
        let s = '';
        for (let i = 0; i < slice.length; i++) s += String.fromCharCode(slice[i]);
        try { return typeof btoa !== 'undefined' ? btoa(s) : s; } catch (_) { return s; }
    }
    _asciiString(off, info) {
        const { length, dataOffset } = this._length(off, info);
        let s = '';
        for (let i = 0; i < length; i++) s += String.fromCharCode(this.buffer[dataOffset + i]);
        return s;
    }
    _utf16String(off, info) {
        const { length, dataOffset } = this._length(off, info);
        let s = '';
        for (let i = 0; i < length; i++) {
            const code = (this.buffer[dataOffset + i * 2] << 8) | this.buffer[dataOffset + i * 2 + 1];
            s += String.fromCharCode(code);
        }
        return s;
    }
    _uid(off, info) {
        const bytes = info + 1;
        let v = 0;
        for (let i = 0; i < bytes; i++) v = v * 256 + this.buffer[off + 1 + i];
        return { UID: v };
    }
    _array(off, info) {
        const { length, dataOffset } = this._length(off, info);
        const arr = new Array(length);
        for (let i = 0; i < length; i++) {
            const ref = this._uintBE(dataOffset + i * this.objectRefSize, this.objectRefSize);
            arr[i] = this._parseObject(ref);
        }
        return arr;
    }
    _dict(off, info) {
        const { length, dataOffset } = this._length(off, info);
        const out = {};
        const keysOff = dataOffset;
        const valsOff = dataOffset + length * this.objectRefSize;
        for (let i = 0; i < length; i++) {
            const keyRef = this._uintBE(keysOff + i * this.objectRefSize, this.objectRefSize);
            const valRef = this._uintBE(valsOff + i * this.objectRefSize, this.objectRefSize);
            const key = this._parseObject(keyRef);
            const val = this._parseObject(valRef);
            if (typeof key === 'string') out[key] = val;
        }
        return out;
    }
}

function decodeUTF8(bytes) {
    try { return new TextDecoder('utf-8').decode(bytes); }
    catch (_) {
        let s = '';
        for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
        return s;
    }
}

function parseXMLPlist(xml) {
    if (typeof DOMParser === 'undefined') return null;
    const doc = new DOMParser().parseFromString(xml, 'text/xml');
    if (doc.querySelector('parsererror')) return null;
    const top = doc.querySelector('plist > dict, plist > array');
    if (!top) return null;
    return _node(top);
}

function _node(node) {
    if (!node) return null;
    switch (node.tagName) {
        case 'string':  return node.textContent;
        case 'integer': return parseInt(node.textContent, 10);
        case 'real':    return parseFloat(node.textContent);
        case 'true':    return true;
        case 'false':   return false;
        case 'date':    return node.textContent;
        case 'data':    return node.textContent.replace(/\s+/g, '');
        case 'array':   return Array.from(node.children).map(_node);
        case 'dict': {
            const obj = {};
            const ch = Array.from(node.children);
            for (let i = 0; i < ch.length; i += 2) {
                if (ch[i]?.tagName === 'key') obj[ch[i].textContent] = _node(ch[i + 1]);
            }
            return obj;
        }
        default: return node.textContent;
    }
}

function parse(data) {
    if (!data || data.length === 0) return null;
    const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
    if (bytes.length < 6) return null;
    let header = '';
    for (let i = 0; i < 6; i++) header += String.fromCharCode(bytes[i]);
    if (header.startsWith('bplist')) {
        try {
            if (typeof self !== 'undefined' && typeof self.plist !== 'undefined') {
                const r = self.plist.parse(bytes.buffer);
                if (r) return r;
            }
        } catch (_) { }
        try {
            return new BinaryPlistParser(bytes).parse();
        } catch (_) { return null; }
    }
    const text = decodeUTF8(bytes);
    if (text.includes('<plist')) {
        try {
            if (typeof self !== 'undefined' && typeof self.plist !== 'undefined') {
                const r = self.plist.parse(text);
                if (r) return r;
            }
        } catch (_) { }
        return parseXMLPlist(text);
    }
    return null;
}

const api = { parse, parseXMLPlist, BinaryPlistParser };

if (typeof module !== 'undefined' && module.exports) {
    module.exports = api;
} else {
    root.IPAA = root.IPAA || {};
    root.IPAA.Plist = api;
}

})(typeof self !== 'undefined' ? self : this);
