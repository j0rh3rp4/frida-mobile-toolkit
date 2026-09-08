'use strict';
/* Optional native TLS reconnaissance and conservative verification bypass module. */
const TARGETS = ['libssl.so', 'libboringssl.so'];
const VERIFY_OK = 1;

function findExport(module, names) {
    for (var i = 0; i < names.length; i++) {
        var address = module.findExportByName(names[i]);
        if (address !== null) return { name: names[i], address: address };
    }
    return null;
}

function install(module) {
    var verify = findExport(module, ['X509_verify_cert']);
    if (verify) {
        Interceptor.attach(verify.address, {
            onLeave: function (retval) {
                if (retval.toInt32() !== VERIFY_OK) {
                    console.log('[native-tls] ' + module.name + ' ' + verify.name + ' -> success');
                    retval.replace(VERIFY_OK);
                }
            }
        });
    }

    ['SSL_set_custom_verify', 'SSL_CTX_set_custom_verify'].forEach(function (name) {
        var address = module.findExportByName(name);
        if (address === null) return;
        Interceptor.attach(address, {
            onEnter: function (args) {
                console.log('[native-tls] observed ' + module.name + '!' + name);
                args[1] = ptr(0);
            }
        });
    });
    console.log('[native-tls] processed ' + module.name);
}

setImmediate(function () {
    TARGETS.forEach(function (name) {
        var module = Process.findModuleByName(name);
        if (module !== null) install(module);
    });
    console.log('[native-tls] loaded. Exports vary by vendor/build; absence is normal.');
});
