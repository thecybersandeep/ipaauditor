(function (root) {
'use strict';

const RULES = [
    { id: 'nsuserdefaults', name: 'NSUserDefaults Insecure Storage', severity: 'warning', confidence: 70,
      patterns: [/\bNSUserDefaults\b/g, /\bUserDefaults\.standard\b/g, /\.standardUserDefaults\b/g],
      description: 'NSUserDefaults stores data unencrypted in plist files; readable from backups.',
      cwe: 'CWE-312', owasp: 'M2', masvs: 'STORAGE-2', category: 'storage' },
    { id: 'coredata', name: 'CoreData Unencrypted Storage', severity: 'warning', confidence: 60,
      patterns: [/\bNSManagedObject\b/g, /\bNSPersistentContainer\b/g, /\bNSManagedObjectContext\b/g],
      description: 'CoreData stores data in an unencrypted SQLite database by default.',
      cwe: 'CWE-312', owasp: 'M2', masvs: 'STORAGE-14', category: 'storage' },
    { id: 'realm', name: 'Realm Database (Check Encryption)', severity: 'warning', confidence: 55,
      patterns: [/\bRealm\.Configuration\b/g, /\bRealmSwift\b/g, /\bRLMRealm\b/g],
      description: 'Realm detected. Ensure encryptionKey is set for sensitive data.',
      cwe: 'CWE-312', owasp: 'M2', masvs: 'STORAGE-14', category: 'storage' },
    { id: 'sqlite', name: 'SQLite Without Encryption', severity: 'warning', confidence: 60,
      patterns: [/\bsqlite3_open\b/g, /\bsqlite3_exec\b/g, /\bFMDatabase\b/g],
      description: 'SQLite data is unencrypted unless SQLCipher is used.',
      cwe: 'CWE-312', owasp: 'M2', masvs: 'STORAGE-14', category: 'storage' },
    { id: 'keychain', name: 'Keychain Secure Storage', severity: 'secure', confidence: 90,
      patterns: [/\bSecItemAdd\b/g, /\bSecItemCopyMatching\b/g, /\bkSecClass[A-Z]\w+\b/g, /\bKeychainSwift\b/g],
      description: 'Keychain APIs detected - recommended for secrets.',
      masvs: 'STORAGE-1', category: 'storage' },
    { id: 'plist_write', name: 'Plist File Write', severity: 'warning', confidence: 55,
      patterns: [/\bwriteToFile:.*?\.plist\b/g, /\bNSKeyedArchiver\b/g, /\bPropertyListSerialization\b/g],
      description: 'Data written to plist files is not encrypted.',
      cwe: 'CWE-312', owasp: 'M2', masvs: 'STORAGE-2', category: 'storage' },

    { id: 'weak_md5', name: 'Weak Hash Algorithm (MD5)', severity: 'high', confidence: 85,
      patterns: [/\bCC_MD5\b/g, /\bkCCHmacAlgMD5\b/g, /CryptoKit\.MD5/g],
      description: 'MD5 is broken. Use SHA-256 or better.',
      cwe: 'CWE-327', owasp: 'M5', masvs: 'CRYPTO-4', category: 'crypto' },
    { id: 'weak_sha1', name: 'Weak Hash Algorithm (SHA1)', severity: 'high', confidence: 80,
      patterns: [/\bCC_SHA1\b/g, /\bkCCHmacAlgSHA1\b/g, /CryptoKit\.Insecure\.SHA1/g],
      description: 'SHA-1 is deprecated; use SHA-256+.',
      cwe: 'CWE-327', owasp: 'M5', masvs: 'CRYPTO-4', category: 'crypto' },
    { id: 'weak_des', name: 'Weak Encryption (DES / 3DES)', severity: 'high', confidence: 90,
      patterns: [/\bkCCAlgorithmDES\b/g, /\bkCCAlgorithm3DES\b/g, /\bDES_ecb_encrypt\b/g],
      description: 'DES/3DES are obsolete. Use AES-256-GCM.',
      cwe: 'CWE-327', owasp: 'M5', masvs: 'CRYPTO-3', category: 'crypto' },
    { id: 'ecb_mode', name: 'ECB Cipher Mode', severity: 'high', confidence: 85,
      patterns: [/\bkCCOptionECBMode\b/g, /\.ECB\b/g],
      description: 'ECB mode leaks patterns. Use CBC + HMAC, or GCM.',
      cwe: 'CWE-327', owasp: 'M5', masvs: 'CRYPTO-3', category: 'crypto' },
    { id: 'insecure_random', name: 'Insecure RNG', severity: 'warning', confidence: 70,
      patterns: [/\brand\s*\(\s*\)/g, /\brandom\s*\(\s*\)/g, /\barc4random\s*\(\s*\)/g, /\bsrand\s*\(/g],
      description: 'Use SecRandomCopyBytes for crypto-grade randomness.',
      cwe: 'CWE-330', owasp: 'M5', masvs: 'CRYPTO-6', category: 'crypto' },

    { id: 'http_url', name: 'Insecure HTTP URL', severity: 'high', confidence: 80,
      patterns: [/\bhttp:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0|[a-zA-Z0-9.-]+\.local\b)[a-zA-Z0-9][a-zA-Z0-9.-]*[^\s"'<>]*/g],
      description: 'Unencrypted HTTP. Use HTTPS or add an ATS exception with justification.',
      cwe: 'CWE-319', owasp: 'M3', masvs: 'NETWORK-1', category: 'network' },
    { id: 'ssl_disabled', name: 'SSL/TLS Validation Disabled', severity: 'high', confidence: 90,
      patterns: [
        /\ballowInvalidCertificates\s*=\s*true\b/gi,
        /\bvalidatesDomainName\s*=\s*false\b/gi,
        /\bSSLPinningMode\.none\b/g,
        /\bcontinueWithoutCredentialForAuthenticationChallenge\b/g,
      ],
      description: 'TLS validation disabled - MITM risk.',
      cwe: 'CWE-295', owasp: 'M3', masvs: 'NETWORK-4', category: 'network' },
    { id: 'ssl_pinning', name: 'SSL/Certificate Pinning Found', severity: 'secure', confidence: 75,
      patterns: [/\bSecTrustEvaluate\b/g, /\bTrustKit\b/g, /\bpinnedCertificates\b/g, /\bevaluateServerTrust\b/g],
      description: 'TLS pinning implementation detected.',
      masvs: 'NETWORK-4', category: 'network' },

    { id: 'logging', name: 'Debug Logging', severity: 'warning', confidence: 50,
      patterns: [/\bNSLog\s*\(/g, /\bos_log\s*\(/g, /\bprint\s*\(/g, /\bdebugPrint\s*\(/g],
      description: 'Logging may leak sensitive data - guard in production.',
      cwe: 'CWE-532', owasp: 'M9', masvs: 'STORAGE-3', category: 'leakage' },
    { id: 'clipboard', name: 'Pasteboard / Clipboard Access', severity: 'warning', confidence: 60,
      patterns: [/\bUIPasteboard\b/g, /\bgeneralPasteboard\b/g],
      description: 'Other apps can read the pasteboard. Clear sensitive data after use.',
      cwe: 'CWE-200', owasp: 'M2', masvs: 'STORAGE-10', category: 'leakage' },
    { id: 'screenshot', name: 'Background-Screenshot Risk', severity: 'info', confidence: 55,
      patterns: [/\bapplicationDidEnterBackground\b/g, /\bwillResignActive\b/g, /\bsceneDidEnterBackground\b/g],
      description: 'iOS snapshots the app when backgrounded. Mask sensitive UI here.',
      cwe: 'CWE-200', owasp: 'M2', masvs: 'STORAGE-9', category: 'leakage' },
    { id: 'cache', name: 'URL/HTTP Cache Usage', severity: 'info', confidence: 50,
      patterns: [/\bURLCache\b/g, /\bNSURLCache\b/g, /\bHTTPCookieStorage\b/g],
      description: 'Cached responses may persist sensitive data. Disable for sensitive endpoints.',
      cwe: 'CWE-524', owasp: 'M2', masvs: 'STORAGE-5', category: 'leakage' },

    { id: 'jailbreak', name: 'Jailbreak Detection', severity: 'secure', confidence: 75,
      patterns: [/\/Applications\/Cydia\.app\b/g, /\bcydia:\/\//g, /\bisJailbroken\b/g, /\/private\/var\/lib\/apt\b/g],
      description: 'Jailbreak detection logic present.',
      masvs: 'RESILIENCE-1', category: 'resilience' },
    { id: 'antidebug', name: 'Anti-Debug Protection', severity: 'secure', confidence: 75,
      patterns: [/\bPT_DENY_ATTACH\b/g, /\bptrace\b/g, /\bP_TRACED\b/g],
      description: 'Anti-debug measures present.',
      masvs: 'RESILIENCE-2', category: 'resilience' },

    { id: 'uiwebview', name: 'Deprecated UIWebView', severity: 'warning', confidence: 90,
      patterns: [/\bUIWebView\b/g],
      description: 'UIWebView is deprecated since iOS 12. Use WKWebView.',
      cwe: 'CWE-919', owasp: 'M1', masvs: 'PLATFORM-5', category: 'platform' },
    { id: 'webview_js', name: 'JavaScript Execution in WebView', severity: 'warning', confidence: 65,
      patterns: [/\bevaluateJavaScript\b/g, /\bstringByEvaluatingJavaScriptFromString\b/g],
      description: 'evaluateJavaScript with untrusted input may enable XSS-like injection.',
      cwe: 'CWE-79', owasp: 'M7', masvs: 'PLATFORM-6', category: 'platform' },
    { id: 'loadhtml_xss', name: 'loadHTMLString XSS Risk', severity: 'high', confidence: 70,
      patterns: [/\bloadHTMLString\b/g],
      description: 'loadHTMLString with untrusted input may inject scripts.',
      cwe: 'CWE-79', owasp: 'M7', masvs: 'PLATFORM-6', category: 'platform' },

    { id: 'biometric', name: 'Biometric Authentication', severity: 'info', confidence: 80,
      patterns: [/\bLAContext\b/g, /\bevaluatePolicy\b/g, /\bbiometryType\b/g, /\bLocalAuthentication\b/g],
      description: 'Biometric authentication (Face ID / Touch ID) used.',
      masvs: 'AUTH-8', category: 'auth' },
    { id: 'file_no_protection', name: 'File Without Data Protection', severity: 'high', confidence: 90,
      patterns: [/\bNSFileProtectionNone\b/g, /\.completeFileProtection\s*=\s*\.none\b/g],
      description: 'File protection disabled - file accessible when device locked.',
      cwe: 'CWE-311', masvs: 'STORAGE-1', category: 'storage' },
    { id: 'file_protected', name: 'File Data Protection Enabled', severity: 'secure', confidence: 85,
      patterns: [/\bNSFileProtectionComplete\b/g, /\bcompleteFileProtection\b/g],
      description: 'Files use complete data protection - locked when device locked.',
      masvs: 'STORAGE-1', category: 'storage' },

    { id: 'objc_swizzle', name: 'Objective-C Method Swizzling', severity: 'info', confidence: 70,
      patterns: [/\bmethod_exchangeImplementations\b/g, /\bclass_addMethod\b/g, /\bobject_setClass\b/g],
      description: 'Runtime method swizzling - can be a security risk if attacker-controllable.',
      masvs: 'RESILIENCE-9', category: 'resilience' },
    { id: 'dynamic_library', name: 'Dynamic Library Loading', severity: 'warning', confidence: 70,
      patterns: [/\bdlopen\s*\(/g, /\bdlsym\s*\(/g, /\bNSBundle\b.*\bload\b/g],
      description: 'dlopen/dlsym can enable code injection if paths are attacker-controllable.',
      cwe: 'CWE-427', masvs: 'RESILIENCE-9', category: 'resilience' },

    { id: 'localhost_url', name: 'Debug / Localhost URL', severity: 'warning', confidence: 75,
      patterns: [/https?:\/\/localhost[:\d]*[^\s"'<>]*/gi, /https?:\/\/127\.0\.0\.1[:\d]*[^\s"'<>]*/gi, /https?:\/\/0\.0\.0\.0[:\d]*[^\s"'<>]*/gi],
      description: 'Localhost / debug URLs - remove before release.',
      cwe: 'CWE-489', owasp: 'M1', masvs: 'CODE-4', category: 'leakage' },

    { id: 'aws_s3_url', name: 'AWS S3 URL', severity: 'warning', confidence: 60,
      patterns: [/https?:\/\/[a-zA-Z0-9.-]*\.?s3[.-][a-zA-Z0-9.-]*\.amazonaws\.com[^\s"'<>]*/gi, /\bs3:\/\/[a-zA-Z0-9.\-]+/gi],
      description: 'S3 bucket reference. Verify bucket is private if used for sensitive data.',
      cwe: 'CWE-200', owasp: 'M1', masvs: 'STORAGE-12', category: 'cloud' },

    { id: 'location_tracking', name: 'Location Access', severity: 'info', confidence: 90,
      patterns: [/\bCLLocationManager\b/g, /\bstartUpdatingLocation\b/g, /\brequestAlwaysAuthorization\b/g],
      description: 'Location access. Confirm consent + minimization.',
      masvs: 'PRIVACY-1', category: 'privacy' },
    { id: 'contacts_access', name: 'Contacts Access', severity: 'info', confidence: 90,
      patterns: [/\bCNContactStore\b/g, /\bABAddressBook\b/g],
      description: 'Contacts access. Ensure justification.',
      masvs: 'PRIVACY-1', category: 'privacy' },
    { id: 'camera_microphone', name: 'Camera / Microphone Access', severity: 'info', confidence: 85,
      patterns: [/\bAVCaptureDevice\b/g, /\bAVAudioSession\b/g],
      description: 'Camera/microphone access. Ensure justification.',
      masvs: 'PRIVACY-1', category: 'privacy' },
];

const TRACKERS = [
    { name: 'Facebook SDK',    patterns: [/\bFBSDKCore\b/, /\bcom\.facebook\b/, /\bFBSDK[A-Z]\w+\b/], category: 'ads' },
    { name: 'Google Analytics',patterns: [/\bGoogleAnalytics\b/, /\bGAI\b/, /\bGTMSession\b/], category: 'analytics' },
    { name: 'Firebase',        patterns: [/\bFirebaseAnalytics\b/, /\bFIRAnalytics\b/, /\bFirebaseCore\b/], category: 'analytics' },
    { name: 'Crashlytics',     patterns: [/\bCrashlytics\b/, /\bFabric\b/], category: 'crash' },
    { name: 'Mixpanel',        patterns: [/\bMixpanel\b/], category: 'analytics' },
    { name: 'Amplitude',       patterns: [/\bAmplitude\b/], category: 'analytics' },
    { name: 'Adjust',          patterns: [/\bAdjustSdk\b/, /\bAdjust\.framework\b/], category: 'attribution' },
    { name: 'AppsFlyer',       patterns: [/\bAppsFlyer\b/, /\bAppsFlyerLib\b/], category: 'attribution' },
    { name: 'Branch',          patterns: [/\bBranchSDK\b/, /\bBranch\.framework\b/], category: 'attribution' },
    { name: 'Segment',         patterns: [/\bSegment\b/, /\bAnalytics\.framework\b/], category: 'analytics' },
    { name: 'Flurry',          patterns: [/\bFlurry\b/], category: 'analytics' },
    { name: 'OneSignal',       patterns: [/\bOneSignal\b/], category: 'push' },
    { name: 'Braze (Appboy)',  patterns: [/\bAppboy\b/, /\bBraze\b/], category: 'engagement' },
    { name: 'Intercom',        patterns: [/\bIntercom\b/], category: 'support' },
    { name: 'Sentry',          patterns: [/\bSentry\b/], category: 'crash' },
    { name: 'New Relic',       patterns: [/\bNewRelic\b/], category: 'apm' },
    { name: 'Bugsnag',         patterns: [/\bBugsnag\b/], category: 'crash' },
    { name: 'Instabug',        patterns: [/\bInstabug\b/], category: 'support' },
    { name: 'RevenueCat',      patterns: [/\bRevenueCat\b/, /\bPurchases\.framework\b/], category: 'iap' },
    { name: 'AdMob',           patterns: [/\bGoogleMobileAds\b/, /\bGADBanner\b/], category: 'ads' },
    { name: 'AppLovin',        patterns: [/\bAppLovin\b/], category: 'ads' },
    { name: 'Unity Ads',       patterns: [/\bUnityAds\b/], category: 'ads' },
    { name: 'ironSource',      patterns: [/\bIronSource\b/], category: 'ads' },
    { name: 'Chartboost',      patterns: [/\bChartboost\b/], category: 'ads' },
    { name: 'Vungle',          patterns: [/\bVungle\b/], category: 'ads' },
    { name: 'AdColony',        patterns: [/\bAdColony\b/], category: 'ads' },
    { name: 'Tapjoy',          patterns: [/\bTapjoy\b/], category: 'ads' },
    { name: 'Mapbox',          patterns: [/\bMapbox\b/], category: 'maps' },
    { name: 'Google Maps',     patterns: [/\bGoogleMaps\b/], category: 'maps' },
    { name: 'Stripe',          patterns: [/\bStripe\.framework\b/, /\bStripeCore\b/], category: 'payments' },
    { name: 'Braintree',       patterns: [/\bBraintree\b/], category: 'payments' },
    { name: 'PayPal',          patterns: [/\bPayPal\b/], category: 'payments' },
    { name: 'AWS SDK',         patterns: [/\bAWSS3\b/, /\bAWSCore\b/, /\bAWSCognito\b/], category: 'cloud' },
    { name: 'Zendesk',         patterns: [/\bZendesk\b/], category: 'support' },
    { name: 'Twilio',          patterns: [/\bTwilio\b/], category: 'comms' },
];

function detectTrackers(text) {
    const out = new Map();
    for (const t of TRACKERS) {
        for (const p of t.patterns) {
            p.lastIndex = 0;
            if (p.test(text)) {
                if (!out.has(t.name)) {
                    out.set(t.name, { name: t.name, category: t.category, matchedPattern: p.source });
                }
                break;
            }
        }
    }
    return [...out.values()];
}

function _lineNumber(content, index) {
    let count = 1;
    for (let i = 0; i < index && i < content.length; i++) {
        if (content.charCodeAt(i) === 10) count++;
    }
    return count;
}

function _snippet(content, index, matchLen) {
    const lines = content.split('\n');
    const beforeIdx = content.lastIndexOf('\n', index);
    let lineStart = beforeIdx + 1;
    let lineEnd = content.indexOf('\n', index + matchLen);
    if (lineEnd === -1) lineEnd = content.length;
    const lineNum = _lineNumber(content, index);
    const startLine = Math.max(0, lineNum - 3);
    const endLine = Math.min(lines.length, lineNum + 2);
    return lines.slice(startLine, endLine).map((line, idx) => {
        const ln = startLine + idx + 1;
        return (ln === lineNum ? '>>>' : '   ') + ' ' + ln + ': ' + line;
    }).join('\n');
}

function scan(content, file, opts) {
    const o = opts || {};
    const findings = [];
    const max = Math.min(content.length, o.maxScanBytes || 10_000_000);
    const scanned = max < content.length ? content.slice(0, max) : content;

    for (const rule of RULES) {
        const enabled = !o.disabledRules || !o.disabledRules.has(rule.id);
        if (!enabled) continue;
        for (const pattern of rule.patterns) {
            pattern.lastIndex = 0;
            let m;
            let count = 0;
            while ((m = pattern.exec(scanned)) !== null) {
                if (++count > 200) break;
                const lineNum = _lineNumber(scanned, m.index);
                findings.push({
                    ruleId: rule.id,
                    ruleName: rule.name,
                    severity: rule.severity,
                    confidence: rule.confidence ?? 60,
                    description: rule.description,
                    cwe: rule.cwe || '', owasp: rule.owasp || '', masvs: rule.masvs || '',
                    category: rule.category || 'other',
                    file,
                    line: lineNum,
                    match: m[0].length > 200 ? m[0].slice(0, 200) + '…' : m[0],
                    snippet: _snippet(scanned, m.index, m[0].length),
                    index: m.index,
                });
                if (m.index === pattern.lastIndex) pattern.lastIndex++;
            }
        }
    }
    return findings;
}

function applyDedupeAndConfidence(findings, opts) {
    const Entropy = (typeof self !== 'undefined' ? self.IPAA : root.IPAA)?.Entropy;
    const o = opts || {};
    const map = new Map();
    for (const f of findings) {
        const key = f.ruleId + '||' + (f.file || '') + '||' + (f.line ?? '') + '||' + (f.match || '').slice(0, 200) + '||' + (f.binaryOffset || '');
        if (map.has(key)) {
            map.get(key).occurrences++;
            continue;
        }
        const f2 = { ...f, occurrences: 1 };
        if (f2.confidence == null && Entropy) f2.confidence = Entropy.computeConfidence(f2);
        if (Entropy) f2.confidenceLabel = Entropy.confidenceLabel(f2.confidence ?? 50);
        map.set(key, f2);
    }
    let result = [...map.values()];
    if (o.minConfidence != null) result = result.filter(f => (f.confidence ?? 0) >= o.minConfidence);
    return result;
}

const api = {
    RULES, TRACKERS,
    scan, detectTrackers,
    dedupe: applyDedupeAndConfidence,
};

if (typeof module !== 'undefined' && module.exports) {
    module.exports = api;
} else {
    root.IPAA = root.IPAA || {};
    root.IPAA.Rules = api;
}

})(typeof self !== 'undefined' ? self : this);
