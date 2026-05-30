(function (root) {
'use strict';

function toJSON(results) {
    const json = {
        tool: { name: 'IPA Auditor', version: '3.0' },
        generatedAt: new Date().toISOString(),
        app: results.appInfo,
        plist: results.plistData,
        permissions: results.permissions,
        urlSchemes: results.urlSchemes,
        queriedSchemes: results.queriedSchemes,
        ats: results.ats,
        provisioning: results.provisioning ? {
            meta: results.provisioning.meta,
            entitlementCount: results.provisioning.entitlementCount,
            entitlementKeys: results.provisioning.entitlementKeys,
            certificates: (results.provisioning.certificates || []).map(c => ({
                subjectCN: c.subjectCN, issuerCN: c.issuerCN,
                validity: c.validity, serial: c.serial,
            })),
            distribution: results.provisioning.meta?.distribution,
        } : null,
        macho: results.machoSummary,
        entitlementsXml: results.entitlementsXml,
        trackers: results.trackers,
        libraries: results.libraries,
        urls: results.urls,
        emails: results.emails,
        summary: results.summary,
        securityScore: results.securityScore,
        findings: results.findings.map(f => ({
            ruleId: f.ruleId,
            ruleName: f.ruleName,
            severity: f.severity,
            confidence: f.confidence,
            confidenceLabel: f.confidenceLabel,
            entropy: f.entropy,
            description: f.description,
            cwe: f.cwe, owasp: f.owasp, masvs: f.masvs,
            category: f.category,
            file: f.file,
            line: f.line,
            match: f.match,
            binaryOffset: f.binaryOffset,
            snippet: f.snippet,
        })),
    };
    return JSON.stringify(json, null, 2);
}

function csvEscape(v) {
    if (v == null) return '';
    const s = String(v);
    if (/[",\n\r]/.test(s)) return '"' + s.replace(/"/g, '""') + '"';
    return s;
}

function toCSV(results) {
    const rows = [
        ['severity', 'confidence', 'rule_id', 'rule_name', 'category', 'cwe', 'owasp', 'masvs', 'file', 'line', 'match', 'binary_offset', 'description'],
    ];
    for (const f of results.findings) {
        rows.push([
            f.severity, f.confidence ?? '', f.ruleId, f.ruleName, f.category || '',
            f.cwe || '', f.owasp || '', f.masvs || '',
            f.file || '', f.line ?? '',
            (f.match || '').slice(0, 500),
            f.binaryOffset || '',
            (f.description || '').slice(0, 500),
        ]);
    }
    return rows.map(r => r.map(csvEscape).join(',')).join('\n');
}

function severityToSarifLevel(s) {
    switch (s) {
        case 'high':    return 'error';
        case 'warning': return 'warning';
        case 'info':    return 'note';
        case 'secure':  return 'note';
        default:        return 'none';
    }
}

function toSARIF(results) {
    const rules = new Map();
    const sarifResults = [];
    for (const f of results.findings) {
        if (!rules.has(f.ruleId)) {
            rules.set(f.ruleId, {
                id: f.ruleId,
                name: f.ruleName,
                shortDescription: { text: f.ruleName },
                fullDescription: { text: f.description || f.ruleName },
                helpUri: f.cwe ? 'https://cwe.mitre.org/data/definitions/' + (f.cwe.replace(/^CWE-/, '')) + '.html' : undefined,
                defaultConfiguration: { level: severityToSarifLevel(f.severity) },
                properties: {
                    severity: f.severity,
                    cwe: f.cwe,
                    owasp: f.owasp,
                    masvs: f.masvs,
                    category: f.category,
                },
            });
        }
        const physical = f.binaryOffset
            ? { artifactLocation: { uri: f.file }, region: { byteOffset: parseInt(f.binaryOffset, 16) || 0 } }
            : { artifactLocation: { uri: f.file }, region: f.line ? { startLine: f.line } : undefined };
        sarifResults.push({
            ruleId: f.ruleId,
            level: severityToSarifLevel(f.severity),
            message: { text: f.description || f.ruleName },
            locations: f.file ? [{ physicalLocation: physical }] : [],
            properties: {
                confidence: f.confidence,
                entropy: f.entropy,
                match: (f.match || '').slice(0, 200),
            },
        });
    }
    return JSON.stringify({
        $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
        version: '2.1.0',
        runs: [{
            tool: {
                driver: {
                    name: 'IPA Auditor',
                    version: '3.0',
                    informationUri: 'https://ipaauditor.com',
                    rules: [...rules.values()],
                },
            },
            artifacts: [{
                location: { uri: results.appInfo?.fileName },
                hashes: results.appInfo?.sha256 ? { 'sha-256': results.appInfo.sha256 } : undefined,
            }],
            results: sarifResults,
            properties: {
                securityScore: results.securityScore,
                summary: results.summary,
                app: results.appInfo,
            },
        }],
    }, null, 2);
}

function download(text, filename, mime) {
    const blob = new Blob([text], { type: mime || 'application/octet-stream' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    setTimeout(() => { document.body.removeChild(a); URL.revokeObjectURL(a.href); }, 1000);
}

function exportFile(kind, results, filenameBase) {
    const base = filenameBase || (results.appInfo?.appName || 'ipa') + '_' + (results.appInfo?.version || '');
    const safeBase = base.replace(/[^a-zA-Z0-9._-]/g, '_');
    if (kind === 'json')  return download(toJSON(results),  safeBase + '_report.json',  'application/json');
    if (kind === 'csv')   return download(toCSV(results),   safeBase + '_findings.csv', 'text/csv');
    if (kind === 'sarif') return download(toSARIF(results), safeBase + '_findings.sarif', 'application/json');
    throw new Error('Unknown export kind: ' + kind);
}

const api = { toJSON, toCSV, toSARIF, exportFile };

if (typeof module !== 'undefined' && module.exports) module.exports = api;
else {
    root.IPAA = root.IPAA || {};
    root.IPAA.Export = api;
}

})(typeof self !== 'undefined' ? self : this);
