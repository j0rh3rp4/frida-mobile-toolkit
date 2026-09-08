'use strict';
/* Optional advanced anti-Frida sanitization. Enable only when the base module is insufficient. */
const MARKERS = ['frida', 'gum-js-loop', 'gmain', 'linjector', 're.frida.server'];
function containsMarker(s) {
    s = String(s || '').toLowerCase();
    return MARKERS.some(function (m) { return s.indexOf(m) !== -1; });
}

setImmediate(function () {
    if (Java.available) Java.perform(function () {
        try {
            var BufferedReader = Java.use('java.io.BufferedReader');
            var readLine = BufferedReader.readLine.overload();
            readLine.implementation = function () {
                var line = readLine.call(this);
                if (line === null) return null;
                var text = String(line).replace(/TracerPid:\s*\d+/i, 'TracerPid:\t0');
                if (containsMarker(text)) return '';
                return text;
            };
            console.log('[anti-frida+] BufferedReader sanitizer installed');
        } catch (e) { console.log('[anti-frida+] Java hook failed: ' + e); }
    });

    var libc = Process.getModuleByName('libc.so');
    ['readlink', 'readlinkat'].forEach(function (name) {
        var address = libc.findExportByName(name);
        if (address === null) return;
        Interceptor.attach(address, {
            onLeave: function (retval) {
                /* Observation only: rewriting arbitrary buffers here is crash-prone. */
                if (retval.toInt32() > 0) console.log('[anti-frida+] observed ' + name);
            }
        });
    });
    console.log('[anti-frida+] native observation hooks installed');
});
