'use strict';
/* Optional Cronet builder module. Keeps Cronet from enforcing configured public-key pins. */
setImmediate(function () {
    if (!Java.available) return;
    Java.perform(function () {
        var installed = false;
        function hookWithFactory(factory) {
            if (installed) return true;
            var Builder = factory.use('org.chromium.net.CronetEngine$Builder');

            if (Builder.addPublicKeyPins) {
                Builder.addPublicKeyPins.overloads.forEach(function (overload) {
                    overload.implementation = function () {
                        console.log('[cronet] ignored addPublicKeyPins for ' + arguments[0]);
                        return this;
                    };
                });
            }

            if (Builder.enablePublicKeyPinningBypassForLocalTrustAnchors) {
                Builder.enablePublicKeyPinningBypassForLocalTrustAnchors.overloads.forEach(function (overload) {
                    overload.implementation = function () {
                        console.log('[cronet] enabled pinning bypass for local trust anchors');
                        return overload.call(this, true);
                    };
                });
            }

            if (Builder.enableQuic) {
                Builder.enableQuic.overloads.forEach(function (overload) {
                    overload.implementation = function () {
                        console.log('[cronet] QUIC disabled to favor proxy-visible TCP/TLS');
                        return overload.call(this, false);
                    };
                });
            }

            installed = true;
            console.log('[cronet] hooks installed');
            return true;
        }

        Java.enumerateClassLoaders({
            onMatch: function (loader) {
                try { hookWithFactory(Java.ClassFactory.get(loader)); } catch (e) {}
            },
            onComplete: function () {
                if (!installed) console.log('[cronet] builder not loaded; use late-loader module too');
            }
        });
    });
});
