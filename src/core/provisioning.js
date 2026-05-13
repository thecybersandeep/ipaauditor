(function (root) {
'use strict';

function findPlistInCMS(bytes) {
    const xmlOpen = [0x3C, 0x3F, 0x78, 0x6D, 0x6C];
    const plistClose = [0x3C, 0x2F, 0x70, 0x6C, 0x69, 0x73, 0x74, 0x3E];

    let start = -1;
    for (let i = 0; i < bytes.length - 5; i++) {
        if (bytes[i] === xmlOpen[0]
            && bytes[i+1] === xmlOpen[1]
            && bytes[i+2] === xmlOpen[2]
            && bytes[i+3] === xmlOpen[3]
            && bytes[i+4] === xmlOpen[4]) {
            start = i;
            break;
        }
    }
    if (start < 0) return null;

    let end = -1;
    for (let i = start + 5; i <= bytes.length - 8; i++) {
        let match = true;
        for (let j = 0; j < 8; j++) {
            if (bytes[i + j] !== plistClose[j]) { match = false; break; }
        }
        if (match) { end = i + 8; break; }
    }
    if (end < 0) return null;
    return { start, end, bytes: bytes.subarray(start, end) };
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
    const doc = new DOMParser().parseFromString(xml, 'text/xml');
    if (doc.querySelector('parsererror')) return null;
    const top = doc.querySelector('plist > dict, plist > array');
    if (!top) return null;
    return parseNode(top);
}

function parseNode(node) {
    if (!node) return null;
    switch (node.tagName) {
        case 'string':  return node.textContent;
        case 'integer': return parseInt(node.textContent, 10);
        case 'real':    return parseFloat(node.textContent);
        case 'true':    return true;
        case 'false':   return false;
        case 'date':    return node.textContent;
        case 'data':    return node.textContent.replace(/\s+/g, '');
        case 'array':   return Array.from(node.children).map(parseNode);
        case 'dict': {
            const obj = {};
            const children = Array.from(node.children);
            for (let i = 0; i < children.length; i += 2) {
                if (children[i]?.tagName === 'key') {
                    obj[children[i].textContent] = parseNode(children[i + 1]);
                }
            }
            return obj;
        }
        default: return node.textContent;
    }
}

function base64Decode(str) {
    const clean = str.replace(/[^A-Za-z0-9+/=]/g, '');
    if (typeof atob !== 'undefined') {
        try {
            const bin = atob(clean);
            const out = new Uint8Array(bin.length);
            for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
            return out;
        } catch (_) { return null; }
    }
    return null;
}

function readDERLength(bytes, offset) {
    const first = bytes[offset];
    if ((first & 0x80) === 0) return { length: first, headerLength: 1 };
    const numBytes = first & 0x7F;
    if (numBytes === 0 || numBytes > 4) return { length: 0, headerLength: 1 + numBytes };
    let length = 0;
    for (let i = 0; i < numBytes; i++) length = (length << 8) | bytes[offset + 1 + i];
    return { length, headerLength: 1 + numBytes };
}

function* walkDER(bytes, start, end) {
    let pos = start;
    while (pos < end) {
        if (pos + 2 > end) return;
        const tag = bytes[pos];
        const { length, headerLength } = readDERLength(bytes, pos + 1);
        const valueStart = pos + 1 + headerLength;
        const valueEnd = valueStart + length;
        if (valueEnd > end) return;
        yield { tag, valueStart, valueEnd, length, totalEnd: valueEnd };
        pos = valueEnd;
    }
}

function parseCertCN(certBytes) {
    if (!certBytes || certBytes.length < 10) return null;
    try {
        const first = walkDER(certBytes, 0, certBytes.length).next().value;
        if (!first) return null;
        const tbsCert = walkDER(certBytes, first.valueStart, first.valueEnd).next().value;
        if (!tbsCert) return null;

        let foundSubject = false;
        let serial = null;
        let validity = null;
        let subjectCN = null;
        let issuerCN = null;

        let seqIdx = 0;
        let serialSeen = false;
        const fields = [];
        for (const item of walkDER(certBytes, tbsCert.valueStart, tbsCert.valueEnd)) {
            fields.push(item);
        }
        let cursor = 0;
        if (fields[cursor] && fields[cursor].tag === 0xA0) cursor++;
        if (fields[cursor] && fields[cursor].tag === 0x02) {
            const v = certBytes.subarray(fields[cursor].valueStart, fields[cursor].valueEnd);
            serial = [...v].map(b => b.toString(16).padStart(2,'0')).join(':');
            cursor++;
        }
        cursor++;
        if (fields[cursor]) {
            issuerCN = extractFirstCN(certBytes, fields[cursor]);
            cursor++;
        }
        if (fields[cursor] && fields[cursor].tag === 0x30) {
            const items = [...walkDER(certBytes, fields[cursor].valueStart, fields[cursor].valueEnd)];
            validity = {
                notBefore: items[0] ? decodeTime(certBytes, items[0]) : null,
                notAfter:  items[1] ? decodeTime(certBytes, items[1]) : null,
            };
            cursor++;
        }
        if (fields[cursor]) {
            subjectCN = extractFirstCN(certBytes, fields[cursor]);
        }

        return { serial, issuerCN, subjectCN, validity };
    } catch (_) {
        return null;
    }
}

function extractFirstCN(bytes, nameItem) {
    const oidCN = [0x55, 0x04, 0x03];
    let foundCN = null;
    for (const rdn of walkDER(bytes, nameItem.valueStart, nameItem.valueEnd)) {
        if (rdn.tag !== 0x31) continue;
        for (const attr of walkDER(bytes, rdn.valueStart, rdn.valueEnd)) {
            if (attr.tag !== 0x30) continue;
            const inner = [...walkDER(bytes, attr.valueStart, attr.valueEnd)];
            if (inner.length < 2) continue;
            const oid = inner[0];
            if (oid.tag !== 0x06 || oid.length !== oidCN.length) continue;
            let matches = true;
            for (let k = 0; k < oidCN.length; k++) {
                if (bytes[oid.valueStart + k] !== oidCN[k]) { matches = false; break; }
            }
            if (matches) {
                const val = inner[1];
                foundCN = decodeUTF8(bytes.subarray(val.valueStart, val.valueEnd));
                return foundCN;
            }
        }
    }
    return foundCN;
}

function decodeTime(bytes, item) {
    const raw = decodeUTF8(bytes.subarray(item.valueStart, item.valueEnd));
    if (item.tag === 0x17 && raw.length >= 12) {
        let yy = parseInt(raw.slice(0,2), 10);
        const yyyy = yy < 50 ? 2000 + yy : 1900 + yy;
        return yyyy + '-' + raw.slice(2,4) + '-' + raw.slice(4,6) + 'T' + raw.slice(6,8) + ':' + raw.slice(8,10) + ':' + raw.slice(10,12) + 'Z';
    }
    if (item.tag === 0x18 && raw.length >= 14) {
        return raw.slice(0,4) + '-' + raw.slice(4,6) + '-' + raw.slice(6,8) + 'T' + raw.slice(8,10) + ':' + raw.slice(10,12) + ':' + raw.slice(12,14) + 'Z';
    }
    return raw;
}

function parse(bytes) {
    if (!(bytes instanceof Uint8Array)) bytes = new Uint8Array(bytes);

    const located = findPlistInCMS(bytes);
    if (!located) return { error: 'No embedded plist found in CMS data', size: bytes.length };

    const xml = decodeUTF8(located.bytes);
    const plist = parseXMLPlist(xml);
    if (!plist) return { error: 'Failed to parse embedded XML plist', xml };

    const certs = (plist.DeveloperCertificates || []).map(b64 => {
        const der = base64Decode(b64);
        if (!der) return { error: 'base64 decode failed' };
        const info = parseCertCN(der);
        return {
            size: der.length,
            ...info,
        };
    });

    const ent = plist.Entitlements || {};
    const entKeys = Object.keys(ent);

    const now = Date.now();
    const expiry = plist.ExpirationDate ? Date.parse(plist.ExpirationDate) : null;
    const expired = expiry != null && expiry < now;

    const flags = {
        getTaskAllow: ent['get-task-allow'] === true,
        provisionsAllDevices: !!plist.ProvisionsAllDevices,
        adHoc: Array.isArray(plist.ProvisionedDevices) && !plist.ProvisionsAllDevices,
        enterprise: !!plist.ProvisionsAllDevices,
        appStore: !plist.ProvisionedDevices && !plist.ProvisionsAllDevices,
        development: ent['get-task-allow'] === true,
    };

    let distribution = 'unknown';
    if (flags.enterprise)  distribution = 'enterprise';
    else if (flags.appStore) distribution = 'app-store';
    else if (flags.development) distribution = 'development';
    else if (flags.adHoc) distribution = 'ad-hoc';

    return {
        size: bytes.length,
        plistOffset: located.start,
        plistSize: located.end - located.start,
        raw: plist,
        xml,
        meta: {
            uuid: plist.UUID || null,
            name: plist.Name || null,
            appIDName: plist.AppIDName || null,
            teamName: plist.TeamName || null,
            teamIdentifier: Array.isArray(plist.TeamIdentifier) ? plist.TeamIdentifier : (plist.TeamIdentifier ? [plist.TeamIdentifier] : []),
            applicationIdentifier: ent['application-identifier'] || null,
            keychainAccessGroups: ent['keychain-access-groups'] || [],
            associatedDomains: ent['com.apple.developer.associated-domains'] || [],
            apsEnvironment: ent['aps-environment'] || null,
            beta: !!plist.BetaReports || !!ent['beta-reports-active'],
            distribution,
            getTaskAllow: flags.getTaskAllow,
            provisionsAllDevices: flags.provisionsAllDevices,
            provisionedDevices: plist.ProvisionedDevices || [],
            deviceCount: (plist.ProvisionedDevices || []).length,
            creationDate: plist.CreationDate || null,
            expirationDate: plist.ExpirationDate || null,
            expired,
            daysUntilExpiry: expiry != null ? Math.floor((expiry - now) / (24 * 60 * 60 * 1000)) : null,
            version: plist.Version || null,
            timeToLive: plist.TimeToLive || null,
        },
        entitlements: ent,
        entitlementCount: entKeys.length,
        entitlementKeys: entKeys,
        certificates: certs,
        flags,
    };
}

const api = { parse, findPlistInCMS };

if (typeof module !== 'undefined' && module.exports) {
    module.exports = api;
} else {
    root.IPAA = root.IPAA || {};
    root.IPAA.Provisioning = api;
}

})(typeof self !== 'undefined' ? self : this);
