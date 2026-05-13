(function (root) {
'use strict';

const TLS_VERSIONS = ['TLSv1.0', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3'];

function tlsVersionRank(v) {
    const i = TLS_VERSIONS.indexOf(v);
    return i < 0 ? 0 : i + 1;
}

function analyze(plistData, filePath) {
    const findings = [];
    const summary = {
        present: false,
        allowsArbitraryLoads: false,
        allowsArbitraryLoadsInWebContent: false,
        allowsArbitraryLoadsForMedia: false,
        allowsLocalNetworking: false,
        domains: [],
        verdict: 'unknown',
    };
    const ats = plistData?.NSAppTransportSecurity;

    if (!ats || typeof ats !== 'object') {
        summary.verdict = 'default-strict';
        findings.push({
            ruleId: 'ats_default',
            ruleName: 'ATS Default Configuration',
            severity: 'secure',
            confidence: 80,
            description: 'No NSAppTransportSecurity dictionary - iOS defaults apply (HTTPS-only, TLS 1.2+).',
            file: filePath, line: null,
            match: 'NSAppTransportSecurity: not present',
            snippet: 'Info.plist does not contain NSAppTransportSecurity. iOS defaults apply.',
            cwe: '', owasp: '', masvs: 'NETWORK-1', category: 'network',
        });
        return { findings, summary };
    }

    summary.present = true;
    summary.allowsArbitraryLoads = ats.NSAllowsArbitraryLoads === true;
    summary.allowsArbitraryLoadsInWebContent = ats.NSAllowsArbitraryLoadsInWebContent === true;
    summary.allowsArbitraryLoadsForMedia = ats.NSAllowsArbitraryLoadsForMedia === true;
    summary.allowsLocalNetworking = ats.NSAllowsLocalNetworking === true;

    if (summary.allowsArbitraryLoads) {
        findings.push({
            ruleId: 'ats_allows_arbitrary_loads',
            ruleName: 'ATS: NSAllowsArbitraryLoads = YES',
            severity: 'high', confidence: 95,
            description: 'NSAllowsArbitraryLoads disables ATS globally - every domain may use plain HTTP and weak TLS.',
            file: filePath, line: null,
            match: 'NSAllowsArbitraryLoads = true',
            snippet: '<key>NSAppTransportSecurity</key>\n<dict>\n>>> <key>NSAllowsArbitraryLoads</key>\n>>> <true/>\n</dict>',
            cwe: 'CWE-319', owasp: 'M3', masvs: 'NETWORK-1', category: 'network',
        });
    }
    if (summary.allowsArbitraryLoadsInWebContent) {
        findings.push({
            ruleId: 'ats_allows_arbitrary_webview',
            ruleName: 'ATS: NSAllowsArbitraryLoadsInWebContent = YES',
            severity: 'high', confidence: 90,
            description: 'WKWebView loads bypass ATS. Verify content sources are trustworthy.',
            file: filePath, line: null,
            match: 'NSAllowsArbitraryLoadsInWebContent = true',
            snippet: '<key>NSAllowsArbitraryLoadsInWebContent</key><true/>',
            cwe: 'CWE-319', owasp: 'M3', masvs: 'NETWORK-1', category: 'network',
        });
    }
    if (summary.allowsArbitraryLoadsForMedia) {
        findings.push({
            ruleId: 'ats_allows_arbitrary_media',
            ruleName: 'ATS: NSAllowsArbitraryLoadsForMedia = YES',
            severity: 'warning', confidence: 85,
            description: 'Media loads (AV) bypass ATS. Acceptable for non-sensitive media; risky otherwise.',
            file: filePath, line: null,
            match: 'NSAllowsArbitraryLoadsForMedia = true',
            snippet: '<key>NSAllowsArbitraryLoadsForMedia</key><true/>',
            cwe: 'CWE-319', masvs: 'NETWORK-1', category: 'network',
        });
    }
    if (summary.allowsLocalNetworking) {
        findings.push({
            ruleId: 'ats_local_networking',
            ruleName: 'ATS: NSAllowsLocalNetworking = YES',
            severity: 'info', confidence: 80,
            description: 'Local-network HTTP is allowed (192.168/10/172, .local). Common in IoT setup flows.',
            file: filePath, line: null,
            match: 'NSAllowsLocalNetworking = true',
            snippet: '<key>NSAllowsLocalNetworking</key><true/>',
            masvs: 'NETWORK-1', category: 'network',
        });
    }

    const domains = ats.NSExceptionDomains || {};
    const entries = Object.entries(domains);
    for (const [domain, config] of entries) {
        if (!config || typeof config !== 'object') continue;
        const row = {
            domain,
            includesSubdomains: config.NSIncludesSubdomains === true,
            allowsInsecureHTTPLoads: config.NSExceptionAllowsInsecureHTTPLoads === true
                                  || config.NSTemporaryExceptionAllowsInsecureHTTPLoads === true,
            minimumTLSVersion: config.NSExceptionMinimumTLSVersion
                            || config.NSTemporaryExceptionMinimumTLSVersion
                            || 'TLSv1.2',
            requiresForwardSecrecy: config.NSExceptionRequiresForwardSecrecy !== false
                                 && config.NSTemporaryExceptionRequiresForwardSecrecy !== false,
            requiresCertificateTransparency: config.NSRequiresCertificateTransparency === true,
            pinnedCAIdentities: !!config.NSPinnedCAIdentities,
            pinnedLeafIdentities: !!config.NSPinnedLeafIdentities,
            issues: [],
        };

        if (row.allowsInsecureHTTPLoads) {
            row.issues.push('http-allowed');
            findings.push({
                ruleId: 'ats_exception_http',
                ruleName: 'ATS Exception: Insecure HTTP for ' + domain,
                severity: 'warning', confidence: 90,
                description: 'Domain "' + domain + '" allows insecure HTTP connections.',
                file: filePath, line: null,
                match: domain + ': NSExceptionAllowsInsecureHTTPLoads = true',
                snippet: '<key>' + domain + '</key>\n<dict>\n>>> <key>NSExceptionAllowsInsecureHTTPLoads</key>\n>>> <true/>\n</dict>',
                cwe: 'CWE-319', owasp: 'M3', masvs: 'NETWORK-1', category: 'network',
            });
        }
        if (tlsVersionRank(row.minimumTLSVersion) < tlsVersionRank('TLSv1.2')) {
            row.issues.push('weak-tls');
            findings.push({
                ruleId: 'ats_weak_tls',
                ruleName: 'ATS: Weak TLS for ' + domain,
                severity: 'high', confidence: 90,
                description: 'Domain "' + domain + '" permits ' + row.minimumTLSVersion + ' (deprecated).',
                file: filePath, line: null,
                match: 'NSExceptionMinimumTLSVersion = ' + row.minimumTLSVersion,
                snippet: '<key>' + domain + '</key>\n<dict>\n>>> <key>NSExceptionMinimumTLSVersion</key>\n>>> <string>' + row.minimumTLSVersion + '</string>\n</dict>',
                cwe: 'CWE-326', owasp: 'M3', masvs: 'NETWORK-2', category: 'network',
            });
        }
        if (!row.requiresForwardSecrecy) {
            row.issues.push('no-pfs');
            findings.push({
                ruleId: 'ats_no_pfs',
                ruleName: 'ATS: PFS Disabled for ' + domain,
                severity: 'warning', confidence: 80,
                description: 'Domain "' + domain + '" disables Forward Secrecy (NSExceptionRequiresForwardSecrecy = false).',
                file: filePath, line: null,
                match: 'NSExceptionRequiresForwardSecrecy = false',
                snippet: '<key>' + domain + '</key>\n<dict>\n>>> <key>NSExceptionRequiresForwardSecrecy</key>\n>>> <false/>\n</dict>',
                cwe: 'CWE-327', masvs: 'NETWORK-2', category: 'network',
            });
        }
        if (row.pinnedCAIdentities || row.pinnedLeafIdentities) {
            findings.push({
                ruleId: 'ats_pinned',
                ruleName: 'ATS: Pinned Certs for ' + domain,
                severity: 'secure', confidence: 90,
                description: 'Domain "' + domain + '" pins ' + (row.pinnedLeafIdentities ? 'leaf' : 'CA') + ' certificate(s) - strong configuration.',
                file: filePath, line: null,
                match: 'NSPinned' + (row.pinnedLeafIdentities ? 'Leaf' : 'CA') + 'Identities present',
                snippet: '<key>' + domain + '</key> contains NSPinned*Identities',
                masvs: 'NETWORK-4', category: 'network',
            });
        }
        summary.domains.push(row);
    }

    if (summary.allowsArbitraryLoads && summary.domains.length === 0) summary.verdict = 'globally-disabled';
    else if (summary.allowsArbitraryLoads) summary.verdict = 'mostly-disabled';
    else if (summary.domains.some(d => d.issues.length > 0)) summary.verdict = 'mixed';
    else if (summary.domains.length > 0) summary.verdict = 'strict-with-exceptions';
    else summary.verdict = 'strict';

    return { findings, summary };
}

const api = { analyze };

if (typeof module !== 'undefined' && module.exports) {
    module.exports = api;
} else {
    root.IPAA = root.IPAA || {};
    root.IPAA.ATS = api;
}

})(typeof self !== 'undefined' ? self : this);
