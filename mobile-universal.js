/*
 * Frida 17+ Android security testing toolkit.
 * Use only on applications and environments you are authorized to assess.
 */
'use strict';

const CONFIG = {
    /*
     * TLS modes:
     *   GLOBAL   - Bypass TLS pinning for every supported connection.
     *   B2C_SAFE - Bypass supported TLS pinning except Microsoft Entra ID,
     *              MSAL, and Azure AD B2C authentication hosts.
     */
    tlsMode: 'GLOBAL',

    rootJava: true,
    rootNative: true,
    antiDebugJava: true,
    antiDebugNative: true,
    antiFridaJava: true,
    antiFridaNative: true,
    tlsJava: true,
    webViewTls: false,
    flutter: false,

    /* Build-specific. Enable Flutter only after validating this signature. */
    flutterPattern: 'ff 03 05 d1 fd 7b 0f a9 bc de 05 94 08 0a 80 52 48'
};

const TLS_EXCLUDED_HOSTS = [
    'b2clogin.com',
    'login.microsoftonline.com',
    'login.windows.net',
    'microsoftonline.com',
    'msauth.net',
    'msftauth.net',
    'msauthimages.net',
    'msftauthimages.net'
];

const ROOT_PACKAGES = [
    'com.noshufou.android.su',
    'com.noshufou.android.su.elite',
    'eu.chainfire.supersu',
    'eu.chainfire.supersu.pro',
    'com.koushikdutta.superuser',
    'com.thirdparty.superuser',
    'com.yellowes.su',
    'com.topjohnwu.magisk',
    'io.github.vvb2060.magisk',
    'org.meowcat.edxposed.manager',
    'org.lsposed.manager',
    'me.weishu.kernelsu',
    'me.bmax.apatch',
    'com.apatch.manager'
];

const ROOT_NAMES = [
    'su', 'busybox', 'supersu', 'superuser.apk', 'kingouser.apk',
    'magisk', 'magiskhide', 'magiskpolicy', 'resetprop', 'daemonsu',
    'zygisk', 'shamiko', 'kernelsu', 'ksud', 'apatch'
];

const ROOT_PATHS = [
    '/system/app/superuser.apk', '/system/app/supersu.apk',
    '/system/bin/su', '/system/xbin/su', '/system/sbin/su', '/sbin/su',
    '/vendor/bin/su', '/su/bin/su', '/data/local/bin/su',
    '/data/local/xbin/su', '/data/local/su', '/data/adb/magisk',
    '/data/adb/modules', '/data/adb/ksu', '/data/adb/ap',
    '/data/adb/apatch', '/sbin/.magisk', '/cache/magisk.log'
];

const ROOT_COMMANDS = [
    'getprop', 'mount', 'build.prop', '/proc/mounts', '/proc/self/mounts',
    'which su', 'command -v su', 'type su', 'busybox', 'magisk',
    'supersu', 'daemonsu', 'kernelsu', 'ksud', 'apatch', 'zygisk', 'shamiko'
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

function log(message) {
    console.log('[mobile] ' + message);
}

function safe(name, callback) {
    try {
        callback();
        log('[+] ' + name);
    } catch (error) {
        log('[-] ' + name + ': ' + error);
    }
}

function lower(value) {
    return String(value === null || value === undefined ? '' : value).toLowerCase();
}

function containsAny(value, list) {
    const text = lower(value);
    return list.some(function (entry) {
        return text.indexOf(lower(entry)) !== -1;
    });
}

function basename(path) {
    const components = lower(path).split('/');
    return components[components.length - 1];
}

function isRootPath(path) {
    return ROOT_NAMES.indexOf(basename(path)) !== -1 || containsAny(path, ROOT_PATHS);
}

function normalizeCommand(command) {
    try {
        if (typeof command === 'string') {
            return command;
        }
        if (command && command.length !== undefined) {
            return Array.prototype.map.call(command, String).join(' ');
        }
    } catch (error) {}
    return String(command || '');
}

function isRootCommand(command) {
    const text = lower(normalizeCommand(command)).trim();
    return containsAny(text, ROOT_COMMANDS) ||
        text === 'su' || text === 'id' ||
        text === '/system/bin/su' || text === '/system/xbin/su';
}

function hostnameMatches(host, configuredHost) {
    const normalizedHost = lower(host).replace(/\.$/, '');
    const normalizedConfiguredHost = lower(configuredHost);
    return normalizedHost === normalizedConfiguredHost ||
        normalizedHost.endsWith('.' + normalizedConfiguredHost);
}

function shouldUseOriginalTls(host) {
    if (CONFIG.tlsMode !== 'B2C_SAFE' || !host) {
        return false;
    }
    return TLS_EXCLUDED_HOSTS.some(function (excludedHost) {
        return hostnameMatches(host, excludedHost);
    });
}

function shouldBypassTls(host) {
    if (CONFIG.tlsMode === 'GLOBAL') {
        return true;
    }
    if (CONFIG.tlsMode === 'B2C_SAFE') {
        return Boolean(host) && !shouldUseOriginalTls(host);
    }
    log('[!] Unknown tlsMode: ' + CONFIG.tlsMode + '. Keeping original TLS validation.');
    return false;
}

function installRootJava() {
    Java.perform(function () {
        safe('PackageManager root checks', function () {
            const PackageManager = Java.use('android.app.ApplicationPackageManager');
            ['getPackageInfo', 'getApplicationInfo'].forEach(function (methodName) {
                if (!PackageManager[methodName]) {
                    return;
                }
                PackageManager[methodName].overloads.forEach(function (overload) {
                    if (!overload.argumentTypes.length ||
                        overload.argumentTypes[0].className !== 'java.lang.String') {
                        return;
                    }
                    overload.implementation = function () {
                        const args = Array.prototype.slice.call(arguments);
                        const packageName = String(args[0]);
                        if (ROOT_PACKAGES.indexOf(packageName) !== -1) {
                            log('hide package: ' + packageName);
                            args[0] = FAKE_PACKAGE;
                        }
                        return overload.call.apply(overload, [this].concat(args));
                    };
                });
            });
        });

        safe('java.io.File root checks', function () {
            const File = Java.use('java.io.File');
            ['exists', 'canExecute', 'canRead'].forEach(function (methodName) {
                const overload = File[methodName].overload();
                overload.implementation = function () {
                    const path = String(this.getAbsolutePath());
                    if (isRootPath(path)) {
                        log('hide root path: ' + path);
                        return false;
                    }
                    return overload.call(this);
                };
            });
        });

        safe('SystemProperties root checks', function () {
            const SystemProperties = Java.use('android.os.SystemProperties');
            SystemProperties.get.overloads.forEach(function (overload) {
                if (!overload.argumentTypes.length ||
                    overload.argumentTypes[0].className !== 'java.lang.String') {
                    return;
                }
                overload.implementation = function () {
                    const args = Array.prototype.slice.call(arguments);
                    const key = String(args[0]);
                    if (Object.prototype.hasOwnProperty.call(ROOT_PROPERTIES, key)) {
                        log('fake property: ' + key);
                        return ROOT_PROPERTIES[key];
                    }
                    return overload.call.apply(overload, [this].concat(args));
                };
            });
        });

        safe('Build tags', function () {
            const Build = Java.use('android.os.Build');
            try { Build.TAGS.value = 'release-keys'; } catch (error) {}
            try { Build.TYPE.value = 'user'; } catch (error) {}
        });

        safe('Runtime.exec root commands', function () {
            const Runtime = Java.use('java.lang.Runtime');
            Runtime.exec.overloads.forEach(function (overload) {
                overload.implementation = function () {
                    const args = Array.prototype.slice.call(arguments);
                    const command = normalizeCommand(args[0]);
                    if (isRootCommand(command)) {
                        log('block Runtime.exec: ' + command);
                        args[0] = overload.argumentTypes[0].className === '[Ljava.lang.String;'
                            ? Java.array('java.lang.String', [FAKE_PATH])
                            : FAKE_PATH;
                    }
                    return overload.call.apply(overload, [this].concat(args));
                };
            });
        });

        safe('ProcessBuilder root commands', function () {
            const ProcessBuilder = Java.use('java.lang.ProcessBuilder');
            const ArrayList = Java.use('java.util.ArrayList');
            const start = ProcessBuilder.start.overload();
            start.implementation = function () {
                const command = String(this.command());
                if (isRootCommand(command)) {
                    log('block ProcessBuilder: ' + command);
                    const replacement = ArrayList.$new();
                    replacement.add(FAKE_PATH);
                    this.command(replacement);
                }
                return start.call(this);
            };
        });

        safe('String build tags', function () {
            const JString = Java.use('java.lang.String');
            const contains = JString.contains.overload('java.lang.CharSequence');
            contains.implementation = function (value) {
                const searched = String(value || '');
                if (searched === 'test-keys' || searched === 'dev-keys') {
                    return false;
                }
                return contains.call(this, value);
            };
        });
    });
}

function installAntiDebugJava() {
    Java.perform(function () {
        safe('Debug.isDebuggerConnected', function () {
            const Debug = Java.use('android.os.Debug');
            Debug.isDebuggerConnected.overload().implementation = function () {
                return false;
            };
        });

        safe('Debug.waitingForDebugger', function () {
            const Debug = Java.use('android.os.Debug');
            Debug.waitingForDebugger.overload().implementation = function () {
                return false;
            };
        });

        safe('Debug.waitForDebugger', function () {
            const Debug = Java.use('android.os.Debug');
            Debug.waitForDebugger.overload().implementation = function () {
                log('skip waitForDebugger');
            };
        });

        safe('ApplicationInfo.FLAG_DEBUGGABLE', function () {
            const ContextWrapper = Java.use('android.content.ContextWrapper');
            const getApplicationInfo = ContextWrapper.getApplicationInfo.overload();
            getApplicationInfo.implementation = function () {
                const applicationInfo = getApplicationInfo.call(this);
                applicationInfo.flags.value = applicationInfo.flags.value & ~2;
                return applicationInfo;
            };
        });
    });
}

function installAntiFridaJava() {
    Java.perform(function () {
        safe('File-based anti-Frida checks', function () {
            const File = Java.use('java.io.File');
            const exists = File.exists.overload();
            exists.implementation = function () {
                const path = String(this.getAbsolutePath());
                if (containsAny(path, FRIDA_MARKERS)) {
                    log('hide Frida path: ' + path);
                    return false;
                }
                return exists.call(this);
            };
        });

        safe('BufferedReader anti-Frida and TracerPid', function () {
            const BufferedReader = Java.use('java.io.BufferedReader');
            const readLine = BufferedReader.readLine.overload();
            readLine.implementation = function () {
                const line = readLine.call(this);
                if (line === null) {
                    return null;
                }
                let text = String(line)
                    .replace(/TracerPid:\s*\d+/i, 'TracerPid:\t0')
                    .replace('ro.build.tags=test-keys', 'ro.build.tags=release-keys')
                    .replace('ro.debuggable=1', 'ro.debuggable=0')
                    .replace('ro.secure=0', 'ro.secure=1');
                if (containsAny(text, FRIDA_MARKERS)) {
                    log('hide Frida marker');
                    return '';
                }
                return text;
            };
        });
    });
}

function getLibc() {
    return Process.getModuleByName('libc.so');
}

function findExport(libc, name) {
    return libc.findExportByName(name);
}

function readCString(pointer) {
    return pointer.readCString();
}

function installNativeHooks() {
    safe('Native root, anti-debug and anti-Frida hooks', function () {
        const libc = getLibc();

        if (CONFIG.rootNative || CONFIG.antiFridaNative) {
            ['fopen', 'open', 'openat', 'access', 'faccessat', 'stat', 'lstat']
                .forEach(function (name) {
                    const address = findExport(libc, name);
                    if (address === null) {
                        return;
                    }
                    Interceptor.attach(address, {
                        onEnter: function (args) {
                            try {
                                const index = name === 'openat' || name === 'faccessat' ? 1 : 0;
                                const path = readCString(args[index]);
                                const hideRoot = CONFIG.rootNative && isRootPath(path);
                                const hideFrida = CONFIG.antiFridaNative && containsAny(path, FRIDA_MARKERS);
                                if (hideRoot || hideFrida) {
                                    this.replacement = Memory.allocUtf8String(FAKE_PATH);
                                    args[index] = this.replacement;
                                    log('hide native path via ' + name + ': ' + path);
                                }
                            } catch (error) {}
                        }
                    });
                });

            const systemAddress = findExport(libc, 'system');
            if (systemAddress !== null) {
                Interceptor.attach(systemAddress, {
                    onEnter: function (args) {
                        try {
                            const command = readCString(args[0]);
                            if (CONFIG.rootNative && isRootCommand(command)) {
                                this.replacement = Memory.allocUtf8String(FAKE_PATH);
                                args[0] = this.replacement;
                                log('block system: ' + command);
                            }
                        } catch (error) {}
                    }
                });
            }

            ['execv', 'execve', 'execvp'].forEach(function (name) {
                const address = findExport(libc, name);
                if (address === null) {
                    return;
                }
                Interceptor.attach(address, {
                    onEnter: function (args) {
                        try {
                            const path = readCString(args[0]);
                            if (CONFIG.rootNative && (isRootPath(path) || isRootCommand(path))) {
                                this.replacement = Memory.allocUtf8String(FAKE_PATH);
                                args[0] = this.replacement;
                                log('block ' + name + ': ' + path);
                            }
                        } catch (error) {}
                    }
                });
            });
        }

        if (CONFIG.antiDebugNative) {
            const ptraceAddress = findExport(libc, 'ptrace');
            if (ptraceAddress !== null) {
                Interceptor.attach(ptraceAddress, {
                    onEnter: function (args) {
                        this.request = args[0].toInt32();
                    },
                    onLeave: function (retval) {
                        if (this.request === 0) {
                            retval.replace(0);
                            log('neutralize ptrace(PTRACE_TRACEME) result');
                        }
                    }
                });
            }
        }
    });
}

function installGlobalTrustManager() {
    Java.perform(function () {
        safe('SSLContext permissive TrustManager', function () {
            const X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
            const SSLContext = Java.use('javax.net.ssl.SSLContext');
            const TrustManager = Java.registerClass({
                name: 'org.mobiletest.TrustManager' + Date.now(),
                implements: [X509TrustManager],
                methods: {
                    checkClientTrusted: function () {},
                    checkServerTrusted: function () {},
                    getAcceptedIssuers: function () {
                        return Java.array('java.security.cert.X509Certificate', []);
                    }
                }
            });
            const managers = Java.array('javax.net.ssl.TrustManager', [TrustManager.$new()]);
            const init = SSLContext.init.overload(
                '[Ljavax.net.ssl.KeyManager;',
                '[Ljavax.net.ssl.TrustManager;',
                'java.security.SecureRandom'
            );
            init.implementation = function (keyManagers, originalManagers, random) {
                log('apply permissive TrustManager');
                return init.call(this, keyManagers, managers, random);
            };
        });
    });
}

function installTlsHooks() {
    Java.perform(function () {
        if (CONFIG.tlsMode === 'GLOBAL') {
            installGlobalTrustManager();
        }

        safe('Conscrypt verifyChain', function () {
            const TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
            TrustManagerImpl.verifyChain.overloads.forEach(function (overload) {
                overload.implementation = function () {
                    const args = Array.prototype.slice.call(arguments);
                    const host = args.length > 2 && args[2] ? String(args[2]) : '';
                    if (shouldBypassTls(host)) {
                        log('[TLS BYPASS] Conscrypt: ' + (host || 'global'));
                        return args[0];
                    }
                    log('[TLS ORIGINAL][AUTH] ' + (host || 'unknown'));
                    return overload.call.apply(overload, [this].concat(args));
                };
            });
        });

        if (CONFIG.tlsMode === 'GLOBAL') {
            safe('Conscrypt checkTrustedRecursive', function () {
                const ArrayList = Java.use('java.util.ArrayList');
                const TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
                TrustManagerImpl.checkTrustedRecursive.overloads.forEach(function (overload) {
                    overload.implementation = function () {
                        return ArrayList.$new();
                    };
                });
            });
        }

        safe('OkHttp CertificatePinner', function () {
            const CertificatePinner = Java.use('okhttp3.CertificatePinner');
            ['check', 'check$okhttp'].forEach(function (methodName) {
                try {
                    CertificatePinner[methodName].overloads.forEach(function (overload) {
                        overload.implementation = function () {
                            const args = Array.prototype.slice.call(arguments);
                            const host = args[0] ? String(args[0]) : '';
                            if (shouldBypassTls(host)) {
                                log('[TLS BYPASS] OkHttp: ' + (host || 'global'));
                                return;
                            }
                            return overload.call.apply(overload, [this].concat(args));
                        };
                    });
                } catch (error) {}
            });
        });

        safe('TrustKit hostname verifier', function () {
            const Verifier = Java.use(
                'com.datatheorem.android.trustkit.pinning.OkHostnameVerifier'
            );
            Verifier.verify.overloads.forEach(function (overload) {
                overload.implementation = function () {
                    const args = Array.prototype.slice.call(arguments);
                    const host = args[0] ? String(args[0]) : '';
                    if (shouldBypassTls(host)) {
                        log('[TLS BYPASS] TrustKit: ' + host);
                        return true;
                    }
                    return overload.call.apply(overload, [this].concat(args));
                };
            });
        });

        if (CONFIG.webViewTls && CONFIG.tlsMode === 'GLOBAL') {
            safe('WebView SSL errors', function () {
                const WebViewClient = Java.use('android.webkit.WebViewClient');
                WebViewClient.onReceivedSslError.overloads.forEach(function (overload) {
                    overload.implementation = function (view, handler, error) {
                        handler.proceed();
                    };
                });
            });
        }
    });
}

function installFlutter() {
    let attempts = 0;
    const timer = setInterval(function () {
        const module = Process.findModuleByName('libflutter.so');
        if (module === null) {
            if (++attempts > 80) {
                clearInterval(timer);
                log('libflutter.so not found');
            }
            return;
        }
        clearInterval(timer);
        const matches = Memory.scanSync(module.base, module.size, CONFIG.flutterPattern);
        if (!matches.length) {
            log('Flutter signature not found; pattern is build-specific');
            return;
        }
        matches.forEach(function (match) {
            let address = match.address;
            if (Process.arch === 'arm') {
                address = address.add(1);
            }
            Interceptor.attach(address, {
                onLeave: function (retval) {
                    retval.replace(1);
                }
            });
        });
        log('Flutter hooks: ' + matches.length);
    }, 250);
}

setImmediate(function () {
    log('Mobile Universal | Frida ' + Frida.version + ' | ' + Process.arch +
        ' | TLS mode: ' + CONFIG.tlsMode);

    if (CONFIG.rootNative || CONFIG.antiDebugNative || CONFIG.antiFridaNative) {
        installNativeHooks();
    }

    if (!Java.available) {
        log('Java runtime unavailable');
        return;
    }

    if (CONFIG.rootJava) {
        installRootJava();
    }
    if (CONFIG.antiDebugJava) {
        installAntiDebugJava();
    }
    if (CONFIG.antiFridaJava) {
        installAntiFridaJava();
    }
    if (CONFIG.tlsJava) {
        installTlsHooks();
    }
    if (CONFIG.flutter) {
        installFlutter();
    }
});
