self.IPAA = self.IPAA || {};

let workerReady = false;
let workerLoadError = null;

try {
    importScripts(
        '../lib/jszip.min.js',
        'core/macho.js',
        'core/plist.js',
        'core/provisioning.js',
        'core/entropy.js',
        'core/rules.js',
        'core/ats.js',
        'core/analyzer.js'
    );
    if (self.IPAA && self.IPAA.Analyzer && typeof self.IPAA.Analyzer.analyzeIPA === 'function') {
        workerReady = true;
    } else {
        workerLoadError = 'IPAA.Analyzer.analyzeIPA not registered after importScripts';
    }
} catch (e) {
    workerLoadError = 'Worker importScripts failed: ' + (e && e.message || e);
}

if (!workerReady) {
    self.postMessage({ type: 'fatal', data: { error: workerLoadError || 'Worker did not initialize' } });
}

function post(type, data) {
    self.postMessage({ type, data });
}

self.onmessage = async (e) => {
    const msg = e.data;
    if (!msg || !msg.type) return;
    if (!workerReady) {
        post('fatal', { error: workerLoadError || 'Worker did not initialize' });
        return;
    }
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
