'use strict';
/* Diagnostics and late class-loader watcher. Does not duplicate the actual bypass modules. */
setImmediate(function () {
    if (!Java.available) return;
    Java.perform(function () {
        var watched = [
            'okhttp3.CertificatePinner',
            'com.scottyab.rootbeer.RootBeer',
            'org.chromium.net.CronetEngine$Builder',
            'com.datatheorem.android.trustkit.pinning.OkHostnameVerifier'
        ];
        var seen = {};
        var ClassLoader = Java.use('java.lang.ClassLoader');

        ClassLoader.loadClass.overloads.forEach(function (overload) {
            overload.implementation = function () {
                var args = Array.prototype.slice.call(arguments);
                var name = args.length ? String(args[0]) : '';
                var result = overload.call.apply(overload, [this].concat(args));
                if (watched.indexOf(name) !== -1 && !seen[name]) {
                    seen[name] = true;
                    console.log('[late-loader] loaded: ' + name);
                    console.log('[late-loader] restart with the corresponding optional module enabled');
                }
                return result;
            };
        });
        console.log('[late-loader] ClassLoader watcher installed');
    });
});
