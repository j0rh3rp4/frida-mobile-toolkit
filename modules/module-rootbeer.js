'use strict';
/* Optional RootBeer bypass module. Load together with mobile-universal-frida17.js. */
setImmediate(function () {
    if (!Java.available) return;
    Java.perform(function () {
        var targets = [
            'isRooted', 'isRootedWithoutBusyBoxCheck', 'isRootedWithBusyBoxCheck',
            'detectRootManagementApps', 'detectPotentiallyDangerousApps',
            'detectRootCloakingApps', 'detectTestKeys', 'checkForBusyBoxBinary',
            'checkForSuBinary', 'checkSuExists', 'checkForRWPaths',
            'checkForDangerousProps', 'checkForRootNative', 'checkForMagiskBinary'
        ];
        var installed = false;
        Java.enumerateClassLoaders({
            onMatch: function (loader) {
                if (installed) return;
                try {
                    var factory = Java.ClassFactory.get(loader);
                    var RootBeer = factory.use('com.scottyab.rootbeer.RootBeer');
                    targets.forEach(function (name) {
                        if (!RootBeer[name]) return;
                        RootBeer[name].overloads.forEach(function (overload) {
                            overload.implementation = function () {
                                console.log('[rootbeer] bypass ' + name);
                                return false;
                            };
                        });
                    });
                    installed = true;
                    console.log('[rootbeer] hooks installed');
                } catch (e) {}
            },
            onComplete: function () {
                if (!installed) console.log('[rootbeer] class not loaded; use late-loader module too');
            }
        });
    });
});
