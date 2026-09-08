/*
 * Frida 16 Android security testing toolkit.
 * Use only on applications and environments you are authorized to assess.
 */
'use strict';

const CONFIG = {
    rootJava: true,
    rootNative: true,
    antiDebugJava: true,
    antiDebugNative: true,
    antiFridaJava: true,
    antiFridaNative: true,
    tlsJava: true,
    webViewTls: false,
    flutter: false,
    flutterPattern: 'ff 03 05 d1 fd 7b 0f a9 bc de 05 94 08 0a 80 52 48'
};
const TLS_MODE = 'GLOBAL';
const ROOT_PACKAGES = [
    'com.noshufou.android.su', 'eu.chainfire.supersu', 'com.koushikdutta.superuser',
    'com.thirdparty.superuser', 'com.yellowes.su', 'com.topjohnwu.magisk',
    'io.github.vvb2060.magisk', 'org.meowcat.edxposed.manager', 'org.lsposed.manager',
    'me.weishu.kernelsu', 'me.bmax.apatch', 'com.apatch.manager'
];
const ROOT_NAMES = [
    'su', 'busybox', 'supersu', 'superuser.apk', 'kingouser.apk', 'magisk',
    'magiskhide', 'magiskpolicy', 'resetprop', 'daemonsu', 'zygisk', 'shamiko',
    'kernelsu', 'ksud', 'apatch'
];
const ROOT_PATHS = [
    '/system/bin/su', '/system/xbin/su', '/sbin/su', '/vendor/bin/su', '/su/bin/su',
    '/data/local/bin/su', '/data/local/xbin/su', '/data/adb/magisk', '/data/adb/modules',
    '/data/adb/ksu', '/data/adb/ap', '/data/adb/apatch', '/sbin/.magisk', '/cache/magisk.log'
];
const ROOT_COMMANDS = [
    'getprop', 'mount', 'build.prop', '/proc/mounts', '/proc/self/mounts',
    'which su', 'command -v su', 'type su', 'busybox', 'magisk', 'supersu',
    'daemonsu', 'kernelsu', 'ksud', 'apatch', 'zygisk', 'shamiko'
];
const FRIDA_MARKERS = [
    'frida-server', 'frida-agent', 'frida-gadget', 're.frida.server',
    'gum-js-loop', 'gmain', 'linjector'
];
const ROOT_PROPERTIES = {
    'ro.build.selinux': '1',
    'ro.debuggable': '0',
    'service.adb.root': '0',
    'ro.secure': '1',
    'ro.build.tags': 'release-keys',
    'ro.build.type': 'user'
};
const FAKE_PACKAGE = 'com.android.package.notfound';
const FAKE_PATH = '/system/bin/__security_test_nonexistent__';

function log(m) {
    console.log('[mobile] ' + m);
}

function safe(name, fn) {
    try {
        fn();
        log('[+] ' + name);
    } catch (e) {
        log('[-] ' + name + ': ' + e);
    }
}

function low(v) {
    return String(v == null ? '' : v).toLowerCase();
}

function containsAny(v, list) {
    const s = low(v);
    return list.some(x => s.indexOf(low(x)) !== -1);
}

function basename(p) {
    const a = low(p).split('/');
    return a[a.length - 1];
}

function isRootPath(p) {
    return ROOT_NAMES.indexOf(basename(p)) !== -1 || containsAny(p, ROOT_PATHS);
}

function normalizeCommand(c) {
    try {
        if (typeof c === 'string') return c;
        if (c && c.length !== undefined) return Array.prototype.map.call(c, String).join(' ');
    } catch (e) {}
    return String(c || '');
}

function isRootCommand(c) {
    const s = low(normalizeCommand(c)).trim();
    return containsAny(s, ROOT_COMMANDS) || s === 'su' || s === 'id' || s === '/system/bin/su' ||
        s === '/system/xbin/su';
}

function bypassTls(host) {
    return true;
}

function installRootJava() {
    Java.perform(function() {
        safe('PackageManager root checks', function() {
            const PM = Java.use('android.app.ApplicationPackageManager');
            ['getPackageInfo', 'getApplicationInfo'].forEach(function(n) {
                if (!PM[n]) return;
                PM[n].overloads.forEach(function(ov) {
                    if (!ov.argumentTypes.length || ov
                        .argumentTypes[0].className !==
                        'java.lang.String') return;
                    ov.implementation = function() {
                        const a = [].slice.call(arguments),
                            p = String(a[0]);
                        if (ROOT_PACKAGES.indexOf(p) !== -1) {
                            log('hide package: ' + p);
                            a[0] = FAKE_PACKAGE;
                        }
                        return ov.call.apply(ov, [this].concat(
                            a));
                    };
                });
            });
        });
        safe('java.io.File root checks', function() {
            const F = Java.use('java.io.File');
            ['exists', 'canExecute', 'canRead'].forEach(function(n) {
                const ov = F[n].overload();
                ov.implementation = function() {
                    const p = String(this.getAbsolutePath());
                    if (isRootPath(p)) {
                        log('hide root path: ' + p);
                        return false;
                    }
                    return ov.call(this);
                };
            });
        });
        safe('SystemProperties root checks', function() {
            const SP = Java.use('android.os.SystemProperties');
            SP.get.overloads.forEach(function(ov) {
                if (!ov.argumentTypes.length || ov.argumentTypes[0]
                    .className !== 'java.lang.String') return;
                ov.implementation = function() {
                    const a = [].slice.call(arguments),
                        k = String(a[0]);
                    if (Object.prototype.hasOwnProperty.call(
                            ROOT_PROPERTIES, k)) {
                        log('fake property: ' + k);
                        return ROOT_PROPERTIES[k];
                    }
                    return ov.call.apply(ov, [this].concat(a));
                };
            });
        });
        safe('Build tags', function() {
            const B = Java.use('android.os.Build');
            try {
                B.TAGS.value = 'release-keys';
            } catch (e) {}
            try {
                B.TYPE.value = 'user';
            } catch (e) {}
        });
        safe('Runtime.exec root commands', function() {
            const R = Java.use('java.lang.Runtime');
            R.exec.overloads.forEach(function(ov) {
                ov.implementation = function() {
                    const a = [].slice.call(arguments),
                        c = normalizeCommand(a[0]);
                    if (isRootCommand(c)) {
                        log('block Runtime.exec: ' + c);
                        a[0] = ov.argumentTypes[0].className ===
                            '[Ljava.lang.String;' ? Java.array(
                                'java.lang.String', [FAKE_PATH]) :
                            FAKE_PATH;
                    }
                    return ov.call.apply(ov, [this].concat(a));
                };
            });
        });
        safe('ProcessBuilder root commands', function() {
            const PB = Java.use('java.lang.ProcessBuilder'),
                AL = Java.use('java.util.ArrayList'),
                start = PB.start.overload();
            start.implementation = function() {
                const c = String(this.command());
                if (isRootCommand(c)) {
                    log('block ProcessBuilder: ' + c);
                    const l = AL.$new();
                    l.add(FAKE_PATH);
                    this.command(l);
                }
                return start.call(this);
            };
        });
        safe('String build tags', function() {
            const S = Java.use('java.lang.String'),
                ov = S.contains.overload('java.lang.CharSequence');
            ov.implementation = function(v) {
                if (v && ['test-keys', 'dev-keys'].indexOf(String(v)) !== -1)
                    return false;
                return ov.call(this, v);
            };
        });
        safe('BufferedReader root properties', function() {
            const BR = Java.use('java.io.BufferedReader'),
                ov = BR.readLine.overload();
            ov.implementation = function() {
                const r = ov.call(this);
                if (r === null) return null;
                return String(r).replace('ro.build.tags=test-keys',
                    'ro.build.tags=release-keys').replace('ro.debuggable=1',
                    'ro.debuggable=0').replace('ro.secure=0', 'ro.secure=1');
            };
        });
    });
}

function installAntiDebugJava() {
    Java.perform(function() {
        safe('Debug.isDebuggerConnected', function() {
            const D = Java.use('android.os.Debug'),
                ov = D.isDebuggerConnected.overload();
            ov.implementation = function() {
                return false;
            };
        });
        safe('Debug.waitingForDebugger', function() {
            const D = Java.use('android.os.Debug'),
                ov = D.waitingForDebugger.overload();
            ov.implementation = function() {
                return false;
            };
        });
        safe('Debug.waitForDebugger', function() {
            const D = Java.use('android.os.Debug'),
                ov = D.waitForDebugger.overload();
            ov.implementation = function() {
                log('skip waitForDebugger');
            };
        });
        safe('ApplicationInfo.FLAG_DEBUGGABLE', function() {
            const C = Java.use('android.content.ContextWrapper'),
                ov = C.getApplicationInfo.overload();
            ov.implementation = function() {
                const ai = ov.call(this);
                ai.flags.value = ai.flags.value & ~2;
                return ai;
            };
        });
    });
}

function installAntiFridaJava() {
    Java.perform(function() {
        safe('File-based anti-Frida checks', function() {
            const F = Java.use('java.io.File'),
                ov = F.exists.overload();
            ov.implementation = function() {
                const p = String(this.getAbsolutePath());
                if (containsAny(p, FRIDA_MARKERS)) {
                    log('hide Frida path: ' + p);
                    return false;
                }
                return ov.call(this);
            };
        });
        safe('BufferedReader anti-Frida and TracerPid', function() {
            const BR = Java.use('java.io.BufferedReader'),
                ov = BR.readLine.overload();
            ov.implementation = function() {
                const r = ov.call(this);
                if (r === null) return null;
                let s = String(r).replace(/TracerPid:\s*\d+/i, 'TracerPid:\t0');
                if (containsAny(s, FRIDA_MARKERS)) {
                    log('hide Frida marker');
                    return '';
                }
                return s;
            };
        });
    });
}

function getLibc() {
    return 'libc.so';
}

function findExport(libc, n) {
    return Module.findExportByName(libc, n);
}

function readCString(p) {
    return Memory.readCString(p);
}

function installNativeHooks() {
    safe('Native root, anti-debug and anti-Frida hooks', function() {
        const libc = getLibc();
        if (CONFIG.rootNative || CONFIG.antiFridaNative) {
            ['fopen', 'open', 'openat', 'access', 'faccessat', 'stat', 'lstat'].forEach(
                function(n) {
                    const a = findExport(libc, n);
                    if (a === null) return;
                    Interceptor.attach(a, {
                        onEnter: function(args) {
                            try {
                                const i = (n === 'openat' || n ===
                                        'faccessat') ? 1 : 0,
                                    p = readCString(args[i]);
                                if ((CONFIG.rootNative && isRootPath(p)) ||
                                    (CONFIG.antiFridaNative && containsAny(
                                        p, FRIDA_MARKERS))) {
                                    this.keep = Memory.allocUtf8String(
                                        FAKE_PATH);
                                    args[i] = this.keep;
                                    log('hide native path via ' + n + ': ' +
                                        p);
                                }
                            } catch (e) {}
                        }
                    });
                });
            const system = findExport(libc, 'system');
            if (system) Interceptor.attach(system, {
                onEnter: function(args) {
                    try {
                        const c = readCString(args[0]);
                        if (CONFIG.rootNative && isRootCommand(c)) {
                            this.keep = Memory.allocUtf8String(FAKE_PATH);
                            args[0] = this.keep;
                            log('block system: ' + c);
                        }
                    } catch (e) {}
                }
            });
            ['execv', 'execve', 'execvp'].forEach(function(n) {
                const a = findExport(libc, n);
                if (!a) return;
                Interceptor.attach(a, {
                    onEnter: function(args) {
                        try {
                            const p = readCString(args[0]);
                            if (CONFIG.rootNative && (isRootPath(p) ||
                                    isRootCommand(p))) {
                                this.keep = Memory.allocUtf8String(
                                    FAKE_PATH);
                                args[0] = this.keep;
                                log('block ' + n + ': ' + p);
                            }
                        } catch (e) {}
                    }
                });
            });
        }
        if (CONFIG.antiDebugNative) {
            const ptrace = findExport(libc, 'ptrace');
            if (ptrace) Interceptor.attach(ptrace, {
                onEnter: function(args) {
                    this.request = args[0].toInt32();
                },
                onLeave: function(ret) {
                    if (this.request === 0) {
                        ret.replace(0);
                        log('neutralize ptrace(PTRACE_TRACEME) result');
                    }
                }
            });
        }
    });
}

function installGlobalTrustManager() {
    Java.perform(function() {
        safe('SSLContext permissive TrustManager', function() {
            const X = Java.use('javax.net.ssl.X509TrustManager'),
                SC = Java.use('javax.net.ssl.SSLContext');
            const T = Java.registerClass({
                name: 'org.mobiletest.TrustManager' + Date.now(),
                implements: [X],
                methods: {
                    checkClientTrusted: function() {},
                    checkServerTrusted: function() {},
                    getAcceptedIssuers: function() {
                        return Java.array(
                            'java.security.cert.X509Certificate', []
                            );
                    }
                }
            });
            const managers = Java.array('javax.net.ssl.TrustManager', [T.$new()]);
            const init = SC.init.overload('[Ljavax.net.ssl.KeyManager;',
                '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom');
            init.implementation = function(k, t, r) {
                log('apply permissive TrustManager');
                return init.call(this, k, managers, r);
            };
        });
    });
}

function installTlsHooks() {
    Java.perform(function() {
        if (TLS_MODE === 'GLOBAL') installGlobalTrustManager();
        safe('Conscrypt verifyChain', function() {
            const T = Java.use('com.android.org.conscrypt.TrustManagerImpl');
            T.verifyChain.overloads.forEach(function(ov) {
                ov.implementation = function() {
                    const a = [].slice.call(arguments),
                        h = a.length > 2 && a[2] ? String(a[2]) : '';
                    if (bypassTls(h)) {
                        log('[TLS BYPASS] Conscrypt: ' + (h ||
                            'global'));
                        return a[0];
                    }
                    log('[TLS ORIGINAL][AUTH] ' + h);
                    return ov.call.apply(ov, [this].concat(a));
                };
            });
        });
        if (TLS_MODE === 'GLOBAL') safe('Conscrypt checkTrustedRecursive', function() {
            const A = Java.use('java.util.ArrayList'),
                T = Java.use('com.android.org.conscrypt.TrustManagerImpl');
            T.checkTrustedRecursive.overloads.forEach(function(ov) {
                ov.implementation = function() {
                    return A.$new();
                };
            });
        });
        safe('OkHttp CertificatePinner', function() {
            const C = Java.use('okhttp3.CertificatePinner');
            ['check', 'check$okhttp'].forEach(function(n) {
                try {
                    C[n].overloads.forEach(function(ov) {
                        ov.implementation = function() {
                            const a = [].slice.call(arguments),
                                h = a[0] ? String(a[0]) : '';
                            if (bypassTls(h)) {
                                log('[TLS BYPASS] OkHttp: ' +
                                h);
                                return;
                            }
                            return ov.call.apply(ov, [this]
                                .concat(a));
                        };
                    });
                } catch (e) {}
            });
        });
        safe('TrustKit hostname verifier', function() {
            const V = Java.use(
                'com.datatheorem.android.trustkit.pinning.OkHostnameVerifier');
            V.verify.overloads.forEach(function(ov) {
                ov.implementation = function() {
                    const a = [].slice.call(arguments),
                        h = a[0] ? String(a[0]) : '';
                    if (bypassTls(h)) {
                        log('[TLS BYPASS] TrustKit: ' + h);
                        return true;
                    }
                    return ov.call.apply(ov, [this].concat(a));
                };
            });
        });
        if (CONFIG.webViewTls) safe('WebView SSL errors', function() {
            const W = Java.use('android.webkit.WebViewClient');
            W.onReceivedSslError.overloads.forEach(function(ov) {
                ov.implementation = function(v, h, e) {
                    h.proceed();
                };
            });
        });
    });
}

function installFlutter() {
    let attempts = 0;
    const timer = setInterval(function() {
        const m = Process.findModuleByName('libflutter.so');
        if (!m) {
            if (++attempts > 80) {
                clearInterval(timer);
                log('libflutter.so not found');
            }
            return;
        }
        clearInterval(timer);
        const hits = Memory.scanSync(m.base, m.size, CONFIG.flutterPattern);
        if (!hits.length) {
            log('Flutter signature not found; pattern is build-specific');
            return;
        }
        hits.forEach(function(x) {
            let a = x.address;
            if (Process.arch === 'arm') a = a.add(1);
            Interceptor.attach(a, {
                onLeave: function(r) {
                    r.replace(1);
                }
            });
        });
        log('Flutter hooks: ' + hits.length);
    }, 250);
}

setImmediate(function() {
    log('Mobile Universal Frida 16 | Frida ' + Frida.version + ' | ' + Process.arch);
    if (CONFIG.rootNative || CONFIG.antiDebugNative || CONFIG.antiFridaNative)
        installNativeHooks();
    if (!Java.available) {
        log('Java runtime unavailable');
        return;
    }
    if (CONFIG.rootJava) installRootJava();
    if (CONFIG.antiDebugJava) installAntiDebugJava();
    if (CONFIG.antiFridaJava) installAntiFridaJava();
    if (CONFIG.tlsJava) installTlsHooks();
    if (CONFIG.flutter) installFlutter();
});
