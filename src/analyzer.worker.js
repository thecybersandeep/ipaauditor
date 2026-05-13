self.IPAA = self.IPAA || {};

try {
    importScripts(
        '../lib/jszip.min.js',
        '../lib/plist.min.js',
        'core/macho.js',
        'core/plist.js',
        'core/provisioning.js',
        'core/entropy.js',
        'core/rules.js',
        'core/ats.js',
        'core/analyzer.js'
    );
} catch (e) {
    self.postMessage({ type: 'fatal', error: 'Worker importScripts failed: ' + e.message });
}

function post(type, data) {
    self.postMessage({ type, data });
}

self.onmessage = async (e) => {
    const msg = e.data;
    if (!msg || !msg.type) return;
    if (msg.type === 'analyze') {
        try {
            const result = await self.IPAA.Analyzer.analyzeIPA(msg.buffer, msg.fileMeta, {
                progress: (kind, payload) => post(kind, payload),
                dedupeOpts: msg.dedupeOpts || {},
            });
            const safe = sanitizeForTransfer(result);
            post('result', safe);
        } catch (err) {
            post('error', { message: err && err.message || String(err), stack: err && err.stack });
        }
    } else if (msg.type === 'ping') {
        post('pong', { ok: true });
    }
};

function sanitizeForTransfer(obj) {
    const seen = new WeakSet();
    function walk(v) {
        if (v == null || typeof v !== 'object') return v;
        if (seen.has(v)) return undefined;
        if (v instanceof ArrayBuffer || ArrayBuffer.isView(v)) return undefined;
        seen.add(v);
        if (Array.isArray(v)) return v.map(walk);
        const out = {};
        for (const k of Object.keys(v)) {
            out[k] = walk(v[k]);
        }
        return out;
    }
    return walk(obj);
}
