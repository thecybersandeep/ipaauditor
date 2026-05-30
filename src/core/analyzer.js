(function (root) {
'use strict';

const IPAA = root.IPAA || (root.IPAA = {});

function formatSize(bytes) {
    if (bytes == null) return '?';
    const u = ['B', 'KB', 'MB', 'GB'];
    let i = 0;
    while (bytes >= 1024 && i < u.length - 1) { bytes /= 1024; i++; }
    return bytes.toFixed(bytes < 10 && i > 0 ? 2 : 1) + ' ' + u[i];
}

async function sha256Hex(bytes) {
    if (typeof crypto === 'undefined' || !crypto.subtle) return null;
    const buf = bytes instanceof ArrayBuffer ? bytes : bytes.buffer;
    const h = await crypto.subtle.digest('SHA-256', buf);
    return [...new Uint8Array(h)].map(b => b.toString(16).padStart(2, '0')).join('');
}

function extractStrings(bytes, minLen) {
    minLen = minLen || 4;
    const out = [];
    let cur = '';
    let start = 0;
    const n = bytes.length;
    for (let i = 0; i < n; i++) {
        const b = bytes[i];
        if (b >= 32 && b <= 126) {
            if (cur.length === 0) start = i;
            cur += String.fromCharCode(b);
        } else {
            if (cur.length >= minLen) out.push({ str: cur, offset: start });
            cur = '';
        }
    }
    if (cur.length >= minLen) out.push({ str: cur, offset: start });
    return out;
}

const TEXT_EXTS = new Set([
    'm', 'mm', 'h', 'c', 'cpp', 'swift',
    'js', 'json', 'xml', 'plist', 'strings', 'stringsdict',
    'html', 'css', 'yaml', 'yml', 'config', 'conf', 'ini',
    'txt', 'csv', 'log', 'mobileconfig',
]);

const PERM_KEYS = {
    NSCameraUsageDescription: 'Camera',
    NSMicrophoneUsageDescription: 'Microphone',
    NSPhotoLibraryUsageDescription: 'Photo Library',
    NSPhotoLibraryAddUsageDescription: 'Photo Library (Add)',
    NSLocationWhenInUseUsageDescription: 'Location (When In Use)',
    NSLocationAlwaysUsageDescription: 'Location (Always)',
    NSLocationAlwaysAndWhenInUseUsageDescription: 'Location (Always & When In Use)',
    NSContactsUsageDescription: 'Contacts',
    NSCalendarsUsageDescription: 'Calendar',
    NSRemindersUsageDescription: 'Reminders',
    NSBluetoothAlwaysUsageDescription: 'Bluetooth',
    NSBluetoothPeripheralUsageDescription: 'Bluetooth (Legacy)',
    NSFaceIDUsageDescription: 'Face ID',
    NSMotionUsageDescription: 'Motion',
    NSHealthShareUsageDescription: 'Health (Share)',
    NSHealthUpdateUsageDescription: 'Health (Update)',
    NSHomeKitUsageDescription: 'HomeKit',
    NSSpeechRecognitionUsageDescription: 'Speech Recognition',
    NSAppleMusicUsageDescription: 'Apple Music',
    NSSiriUsageDescription: 'Siri',
    NSUserTrackingUsageDescription: 'App Tracking (IDFA)',
    NSNearbyInteractionUsageDescription: 'Nearby Interaction',
    NSLocalNetworkUsageDescription: 'Local Network',
    NFCReaderUsageDescription: 'NFC',
};

function extractPermissions(plistData) {
    const out = {};
    if (!plistData) return out;
    for (const [k, label] of Object.entries(PERM_KEYS)) {
        if (plistData[k]) out[k] = { name: label, reason: plistData[k] };
    }
    return out;
}

function bundleAppInfo(plistData, file, hash) {
    return {
        fileName: file.name,
        fileSize: formatSize(file.size),
        fileSizeBytes: file.size,
        sha256: hash,
        appName: plistData?.CFBundleDisplayName || plistData?.CFBundleName || 'Unknown',
        bundleId: plistData?.CFBundleIdentifier || '',
        version: plistData?.CFBundleShortVersionString || '',
        build: plistData?.CFBundleVersion || '',
        minOS: plistData?.MinimumOSVersion || '',
        executableName: plistData?.CFBundleExecutable || '',
        supportedPlatforms: plistData?.CFBundleSupportedPlatforms || [],
        dtPlatformBuild: plistData?.DTPlatformBuild || '',
        dtPlatformVersion: plistData?.DTPlatformVersion || '',
        dtXcode: plistData?.DTXcode || '',
        dtXcodeBuild: plistData?.DTXcodeBuild || '',
    };
}

function isPNG(b) { return b.length > 8 && b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4E && b[3] === 0x47; }
function isJPEG(b) { return b.length > 3 && b[0] === 0xFF && b[1] === 0xD8 && b[2] === 0xFF; }
function isCrushedPNG(b) {
    if (!isPNG(b)) return false;
    for (let i = 8; i < Math.min(b.length, 100); i++) {
        if (b[i] === 0x43 && b[i+1] === 0x67 && b[i+2] === 0x42 && b[i+3] === 0x49) return true;
    }
    return false;
}

function bytesToBase64DataURL(bytes, mime) {
    let s = '';
    for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return 'data:' + (mime || 'image/png') + ';base64,' + (typeof btoa !== 'undefined' ? btoa(s) : '');
}

async function analyzeIPA(arrayBuffer, fileMeta, opts) {
    const post = opts?.progress || (() => {});
    const { Rules, ATS, MachO, Provisioning, Plist, Entropy } = IPAA;

    post('progress', { stage: 'reading', percent: 5, text: 'Reading IPA…' });

    const hash = await sha256Hex(arrayBuffer);

    post('progress', { stage: 'unzip', percent: 10, text: 'Unzipping…' });

    if (typeof JSZip === 'undefined') throw new Error('JSZip not loaded');
    const zip = await JSZip.loadAsync(arrayBuffer);

    let appPath = null;
    for (const path of Object.keys(zip.files)) {
        const m = path.match(/^Payload\/([^\/]+\.app)\//i);
        if (m) { appPath = 'Payload/' + m[1] + '/'; break; }
    }
    if (!appPath) throw new Error('No .app bundle found in IPA');

    post('progress', { stage: 'tree', percent: 15, text: 'Indexing files…' });

    const allFiles = [];
    const fileTree = {};
    const specialFiles = { databases: [], plists: [], certificates: [], configs: [], frameworks: [], appex: [] };

    for (const [path, entry] of Object.entries(zip.files)) {
        if (entry.dir || path.includes('__MACOSX')) continue;
        const relPath = path.startsWith(appPath) ? path.slice(appPath.length) : path;
        allFiles.push({ path: relPath, fullPath: path, size: entry._data?.uncompressedSize || 0 });

        const ext = relPath.split('.').pop().toLowerCase();
        const lower = relPath.toLowerCase();
        if (['db','sqlite','sqlite3','realm'].includes(ext)) specialFiles.databases.push(relPath);
        if (ext === 'plist') specialFiles.plists.push(relPath);
        if (['cer','pem','crt','p12','key','der'].includes(ext)) specialFiles.certificates.push(relPath);
        if (['json','xml','yaml','yml','config'].includes(ext)) specialFiles.configs.push(relPath);
        if (lower.includes('.framework/')) {
            const fw = lower.split('.framework/')[0].split('/').pop() + '.framework';
            if (!specialFiles.frameworks.includes(fw)) specialFiles.frameworks.push(fw);
        }
        if (lower.includes('.appex/')) {
            const ex = lower.split('.appex/')[0].split('/').pop() + '.appex';
            if (!specialFiles.appex.includes(ex)) specialFiles.appex.push(ex);
        }

        const parts = relPath.split('/');
        let cur = fileTree;
        for (let i = 0; i < parts.length; i++) {
            const p = parts[i];
            if (i === parts.length - 1) {
                cur[p] = { _type: 'file', _path: relPath, _size: entry._data?.uncompressedSize || 0 };
            } else {
                cur[p] = cur[p] || { _type: 'dir' };
                cur = cur[p];
            }
        }
    }

    post('progress', { stage: 'plist', percent: 20, text: 'Parsing Info.plist…' });

    const plistFile = zip.file(appPath + 'Info.plist');
    let plistData = null;
    if (plistFile) {
        const buf = await plistFile.async('arraybuffer');
        plistData = Plist.parse(new Uint8Array(buf));
    }
    const appInfo = bundleAppInfo(plistData, fileMeta, hash);
    const permissions = extractPermissions(plistData);

    const urlSchemes = [];
    let queriedSchemes = [];
    if (plistData) {
        const urlTypes = plistData.CFBundleURLTypes;
        if (Array.isArray(urlTypes)) {
            for (const t of urlTypes) {
                if (Array.isArray(t.CFBundleURLSchemes)) urlSchemes.push(...t.CFBundleURLSchemes);
            }
        }
        if (Array.isArray(plistData.LSApplicationQueriesSchemes)) queriedSchemes = plistData.LSApplicationQueriesSchemes;
    }

    let appIcon = null;
    if (plistData) {
        const iconFiles = plistData.CFBundleIcons?.CFBundlePrimaryIcon?.CFBundleIconFiles
                       || plistData['CFBundleIcons~ipad']?.CFBundlePrimaryIcon?.CFBundleIconFiles
                       || plistData.CFBundleIconFiles || [];
        if (iconFiles.length > 0) {
            const iconName = iconFiles[iconFiles.length - 1];
            const candidates = [
                appPath + iconName + '@3x.png',
                appPath + iconName + '@2x.png',
                appPath + iconName + '.png',
                appPath + 'AppIcon60x60@3x.png',
                appPath + 'AppIcon60x60@2x.png',
                appPath + 'AppIcon76x76@2x~ipad.png',
            ];
            for (const p of candidates) {
                const f = zip.file(p);
                if (f) {
                    try {
                        const data = new Uint8Array(await f.async('arraybuffer'));
                        if (!isCrushedPNG(data)) {
                            appIcon = bytesToBase64DataURL(data, 'image/png');
                        }
                    } catch (_) { }
                    break;
                }
            }
        }
    }

    const atsResult = ATS.analyze(plistData, 'Info.plist');
    const findings = [...atsResult.findings];

    post('progress', { stage: 'scan-files', percent: 30, text: 'Scanning source files…', current: 0, total: allFiles.length });

    let scanned = 0;
    const filesToScan = allFiles.filter(f => {
        const ext = f.path.split('.').pop().toLowerCase();
        return TEXT_EXTS.has(ext);
    });

    const allUrls = [];
    const allEmails = [];

    for (const fileMeta2 of filesToScan) {
        try {
            const entry = zip.file(fileMeta2.fullPath);
            if (!entry) { scanned++; continue; }
            let content;
            const ext = fileMeta2.path.split('.').pop().toLowerCase();
            if (ext === 'plist') {
                const buf = await entry.async('arraybuffer');
                const bytes = new Uint8Array(buf);
                let header = '';
                for (let i = 0; i < Math.min(6, bytes.length); i++) header += String.fromCharCode(bytes[i]);
                if (header.startsWith('bplist')) {
                    const parsed = Plist.parse(bytes);
                    content = parsed ? JSON.stringify(parsed, null, 2) : '';
                } else {
                    content = await entry.async('string');
                }
            } else {
                content = await entry.async('string');
            }

            if (content && content.length > 0) {
                const fileFindings = Rules.scan(content, fileMeta2.path, { maxScanBytes: 4_000_000 });
                findings.push(...fileFindings);

                const secrets = Entropy.detectSecrets(content);
                for (const s of secrets) {
                    s.file = fileMeta2.path;
                    s.line = lineOf(content, s.index);
                    s.snippet = snippetOf(content, s.index, s.match.length);
                    findings.push(s);
                }

                const urls = content.match(/https?:\/\/[^\s"'<>\]\)]+/gi);
                if (urls) allUrls.push(...urls);
                const emails = content.match(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g);
                if (emails) allEmails.push(...emails);
            }
        } catch (_) { }
        scanned++;
        if (scanned % 20 === 0 || scanned === filesToScan.length) {
            const pct = 30 + Math.floor(20 * scanned / Math.max(1, filesToScan.length));
            post('progress', { stage: 'scan-files', percent: pct, text: 'Scanned ' + scanned + ' / ' + filesToScan.length + ' files', current: scanned, total: filesToScan.length, file: fileMeta2.path });
        }
    }

    post('progress', { stage: 'binary', percent: 55, text: 'Analyzing executable…' });

    let macho = null;
    let machoSummary = null;
    let binType = 'Unknown';
    let binaryStrings = [];
    let libraries = [];
    let entitlementsXml = null;
    if (appInfo.executableName) {
        const binPath = appPath + appInfo.executableName;
        const f = zip.file(binPath);
        if (f) {
            const buf = await f.async('arraybuffer');
            const bytes = new Uint8Array(buf);

            post('progress', { stage: 'binary', percent: 58, text: 'Parsing Mach-O headers…' });
            macho = MachO.parse(bytes);
            machoSummary = MachO.summarize(macho);

            if (machoSummary) {
                if (machoSummary.type === 'fat') {
                    binType = machoSummary.slices?.[0]?.checksec?.swift ? 'Swift' : 'Objective-C';
                    libraries = (machoSummary.slices?.[0]?.dylibs || []);
                    entitlementsXml = machoSummary.slices?.find(s => s.entitlementsXml)?.entitlementsXml || null;
                } else {
                    binType = machoSummary.checksec?.swift ? 'Swift' : 'Objective-C';
                    libraries = machoSummary.dylibs || [];
                    entitlementsXml = machoSummary.entitlementsXml || null;
                }
            }

            post('progress', { stage: 'strings', percent: 65, text: 'Extracting strings from binary…' });
            binaryStrings = extractStrings(bytes, 5);
            const stringsContent = binaryStrings.map(s => s.str).join('\n');

            post('progress', { stage: 'binary-scan', percent: 70, text: 'Scanning binary strings…' });
            const binFindings = Rules.scan(stringsContent, 'BINARY:' + appInfo.executableName, { maxScanBytes: 16_000_000 });
            for (const f2 of binFindings) {
                const ms = binaryStrings.find(s => s.str.includes(f2.match));
                if (ms) f2.binaryOffset = '0x' + ms.offset.toString(16);
            }
            findings.push(...binFindings);

            const secretsInBinary = Entropy.detectSecrets(stringsContent);
            for (const s of secretsInBinary) {
                const ms = binaryStrings.find(x => x.str.includes(s.match));
                s.file = 'BINARY:' + appInfo.executableName;
                if (ms) s.binaryOffset = '0x' + ms.offset.toString(16);
                findings.push(s);
            }

            const binUrls = stringsContent.match(/https?:\/\/[^\s"'<>\]\)]+/gi);
            if (binUrls) allUrls.push(...binUrls);
        }
    }

    post('progress', { stage: 'provisioning', percent: 76, text: 'Decoding embedded.mobileprovision…' });

    let provisioning = null;
    const provFile = zip.file(appPath + 'embedded.mobileprovision');
    if (provFile) {
        const data = new Uint8Array(await provFile.async('arraybuffer'));
        provisioning = Provisioning.parse(data);

        if (provisioning && provisioning.meta) {
            if (provisioning.meta.expired) {
                findings.push({
                    ruleId: 'prov_expired',
                    ruleName: 'Provisioning Profile Expired',
                    severity: 'high', confidence: 100,
                    description: 'The embedded provisioning profile expired on ' + provisioning.meta.expirationDate + '.',
                    file: 'embedded.mobileprovision', line: null,
                    match: 'Expired ' + provisioning.meta.expirationDate,
                    snippet: 'ExpirationDate: ' + provisioning.meta.expirationDate,
                    cwe: '', owasp: 'M9', masvs: '',
                    category: 'provisioning',
                });
            } else if (provisioning.meta.daysUntilExpiry != null && provisioning.meta.daysUntilExpiry < 30) {
                findings.push({
                    ruleId: 'prov_expiring_soon',
                    ruleName: 'Provisioning Profile Expiring Soon',
                    severity: 'warning', confidence: 100,
                    description: 'Profile expires in ' + provisioning.meta.daysUntilExpiry + ' days (' + provisioning.meta.expirationDate + ').',
                    file: 'embedded.mobileprovision', line: null,
                    match: provisioning.meta.daysUntilExpiry + ' days',
                    snippet: 'ExpirationDate: ' + provisioning.meta.expirationDate,
                    cwe: '', masvs: '',
                    category: 'provisioning',
                });
            }
            if (provisioning.meta.getTaskAllow) {
                findings.push({
                    ruleId: 'prov_get_task_allow',
                    ruleName: 'get-task-allow Enabled (Debug Build)',
                    severity: 'high', confidence: 100,
                    description: 'get-task-allow entitlement is true - this is a DEBUG build. Should not be shipped.',
                    file: 'embedded.mobileprovision', line: null,
                    match: 'get-task-allow = true',
                    snippet: 'Entitlements.get-task-allow = true',
                    cwe: 'CWE-489', owasp: 'M7', masvs: 'RESILIENCE-3',
                    category: 'provisioning',
                });
            }
        }
    }

    post('progress', { stage: 'trackers', percent: 82, text: 'Detecting trackers/SDKs…' });

    const fileListText = allFiles.map(f => f.path).join('\n');
    const binStringsText = binaryStrings.map(s => s.str).join('\n');
    const trackersByFile = Rules.detectTrackers(fileListText);
    const trackersByBinary = Rules.detectTrackers(binStringsText);
    const trackersMap = new Map();
    for (const t of [...trackersByFile, ...trackersByBinary]) trackersMap.set(t.name, t);
    const trackers = [...trackersMap.values()];

    if (specialFiles.databases.length > 0) {
        findings.push({
            ruleId: 'database_files', ruleName: 'Database Files in Bundle',
            severity: 'warning', confidence: 80,
            description: 'Database files shipped in the bundle. Verify they contain no sensitive prepopulated data.',
            file: specialFiles.databases[0], line: null,
            match: specialFiles.databases.join(', '),
            snippet: 'Found database files:\n' + specialFiles.databases.map(f => '  - ' + f).join('\n'),
            cwe: 'CWE-312', owasp: 'M2', masvs: 'STORAGE-14',
            category: 'storage',
        });
    }
    if (specialFiles.certificates.length > 0) {
        findings.push({
            ruleId: 'cert_files', ruleName: 'Embedded Certificate/Key Material',
            severity: 'info', confidence: 80,
            description: 'Certificate/key files in bundle. If they contain private keys this is high risk.',
            file: specialFiles.certificates[0], line: null,
            match: specialFiles.certificates.join(', '),
            snippet: specialFiles.certificates.map(f => '  - ' + f).join('\n'),
            cwe: 'CWE-321', masvs: 'CRYPTO-1',
            category: 'crypto',
        });
    }

    post('progress', { stage: 'dedupe', percent: 88, text: 'Scoring & deduping findings…' });

    const deduped = Rules.dedupe(findings, opts?.dedupeOpts || {});

    const grouped = groupByRule(deduped);

    const total = {
        high:    grouped.high.length,
        warning: grouped.warning.length,
        info:    grouped.info.length,
        secure:  grouped.secure.length,
    };

    const score = computeScore(deduped, grouped, machoSummary);

    post('progress', { stage: 'done', percent: 100, text: 'Done!' });

    return {
        version: 3,
        generatedAt: new Date().toISOString(),
        appPath,
        appInfo,
        plistData,
        permissions,
        urlSchemes,
        queriedSchemes,
        appIcon,
        files: allFiles.map(f => f.path),
        fileTree,
        specialFiles,
        macho,
        machoSummary,
        binType,
        binaryStringCount: binaryStrings.length,
        libraries,
        entitlementsXml,
        ats: atsResult.summary,
        provisioning,
        trackers,
        urls: [...new Set(allUrls)].slice(0, 2000),
        emails: [...new Set(allEmails)].slice(0, 200),
        findings: deduped,
        groupedFindings: grouped,
        summary: total,
        securityScore: score,
    };
}

function lineOf(content, index) {
    let count = 1;
    for (let i = 0; i < index && i < content.length; i++) {
        if (content.charCodeAt(i) === 10) count++;
    }
    return count;
}

function snippetOf(content, index, matchLen) {
    const lines = content.split('\n');
    const lineNum = lineOf(content, index);
    const startLine = Math.max(0, lineNum - 3);
    const endLine = Math.min(lines.length, lineNum + 2);
    return lines.slice(startLine, endLine).map((line, idx) => {
        const ln = startLine + idx + 1;
        return (ln === lineNum ? '>>>' : '   ') + ' ' + ln + ': ' + (line.length > 240 ? line.slice(0, 240) + '…' : line);
    }).join('\n');
}

function groupByRule(findings) {
    const grouped = { high: [], warning: [], info: [], secure: [] };
    const map = new Map();
    for (const f of findings) {
        const key = f.ruleId;
        if (!map.has(key)) {
            map.set(key, {
                ruleId: f.ruleId,
                ruleName: f.ruleName,
                severity: f.severity,
                description: f.description,
                cwe: f.cwe, owasp: f.owasp, masvs: f.masvs,
                category: f.category || 'other',
                instances: [],
                avgConfidence: 0,
            });
        }
        map.get(key).instances.push({
            file: f.file,
            line: f.line,
            match: f.match,
            snippet: f.snippet,
            binaryOffset: f.binaryOffset,
            confidence: f.confidence,
            confidenceLabel: f.confidenceLabel,
            entropy: f.entropy,
        });
    }
    for (const g of map.values()) {
        const sum = g.instances.reduce((acc, i) => acc + (i.confidence ?? 50), 0);
        g.avgConfidence = Math.round(sum / Math.max(1, g.instances.length));
        const sev = grouped[g.severity] ? g.severity : 'info';
        grouped[sev].push(g);
    }
    for (const k of Object.keys(grouped)) {
        grouped[k].sort((a, b) => (b.avgConfidence - a.avgConfidence) || (b.instances.length - a.instances.length));
    }
    return grouped;
}

function computeScore(findings, grouped, machoSummary) {
    let score = 100;
    const groups = [
        ...(grouped?.high    || []),
        ...(grouped?.warning || []),
        ...(grouped?.info    || []),
        ...(grouped?.secure  || []),
    ];

    const weights = { high: 10, warning: 3, info: 0.3, secure: -2 };
    let penalty = 0;
    let bonus = 0;
    for (const g of groups) {
        const w = weights[g.severity] ?? 0;
        if (w === 0) continue;
        const conf = (g.avgConfidence ?? 50) / 100;
        const n = Math.max(1, g.instances?.length || 1);
        const mult = Math.min(3, 1 + Math.log10(n));
        const delta = w * conf * mult;
        if (delta >= 0) penalty += delta;
        else            bonus   += -delta;
    }
    penalty = Math.min(penalty, 80);
    bonus   = Math.min(bonus, 15);
    score -= penalty;
    score += bonus;

    const cs = machoSummary?.checksec || (machoSummary?.slices?.[0]?.checksec);
    if (cs) {
        if (cs.pie)             score += 2; else score -= 6;
        if (cs.stackCanary)     score += 1; else score -= 3;
        if (cs.codeSigned)      score += 1; else score -= 5;
        if (cs.allowsStackExec) score -= 4;
    }

    return Math.max(0, Math.min(100, Math.round(score)));
}

const api = {
    analyzeIPA,
    extractStrings,
    sha256Hex,
    formatSize,
};

if (typeof module !== 'undefined' && module.exports) {
    module.exports = api;
} else {
    IPAA.Analyzer = api;
}

})(typeof self !== 'undefined' ? self : this);
