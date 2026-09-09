# Frida Android Security Testing Toolkit

A modular Frida 17+ toolkit for authorized Android application security testing. It provides reusable bypasses for common root detection, TLS pinning, anti-debugging, and anti-Frida controls.

> Use these scripts only against applications and environments you own or are explicitly authorized to assess.

## Main Script

### `mobile-universal.js`

The main script includes:

- Java and native root-detection bypasses
- Coverage for Magisk, KernelSU, APatch, Zygisk, Shamiko, LSPosed, and related artifacts
- Java and native anti-debugging hooks
- Basic anti-Frida countermeasures
- TLS pinning bypasses for `SSLContext`, Conscrypt, OkHttp, and TrustKit
- Integrated late ClassLoader handling for OkHttp and TrustKit
- Optional WebView and Flutter support

## Configuration

Set the TLS mode near the beginning of the script:

```javascript
/*
 * TLS modes:
 *   GLOBAL   - Bypass TLS pinning for every supported connection.
 *   B2C_SAFE - Bypass supported TLS pinning except Microsoft Entra ID,
 *              MSAL, and Azure AD B2C authentication hosts.
 */
tlsMode: 'GLOBAL',
```

Use `GLOBAL` for normal testing. Use `B2C_SAFE` only when a global TLS bypass breaks a Microsoft authentication flow.

Late TLS handling is enabled by default:

```javascript
/* Install OkHttp and TrustKit hooks when classes appear in late ClassLoaders. */
lateTlsHooks: true,
```

The script first scans existing class loaders, then monitors `ClassLoader.loadClass()` and installs OkHttp or TrustKit hooks once the relevant class becomes available. Duplicate hooks are prevented per class loader.

## Optional Modules

Load optional modules alongside the main script with additional `-l` arguments:

- `module-rootbeer.js`: Directly hooks common RootBeer detection methods.
- `module-cronet.js`: Disables configured Cronet public-key pins, enables local trust-anchor bypass, and disables QUIC.
- `module-native-tls.js`: Adds conservative hooks for common native OpenSSL and BoringSSL verification functions.
- `module-antifrida-advanced.js`: Adds extra Frida-marker filtering and native anti-Frida reconnaissance.


## Usage

Run the main script:

```bash
frida -U -f com.example.app \
  -l mobile-universal.js
```

Load optional modules only when required:

```bash
frida -U -f com.example.app \
  -l mobile-universal.js \
  -l module-rootbeer.js \
  -l module-cronet.js
```

## Recommended Workflow

1. Start with `mobile-universal.js` and `tlsMode: 'GLOBAL'`.
2. Keep `lateTlsHooks: true` for applications using dynamic or split class loaders.
3. Add RootBeer or Cronet modules only when those technologies are present.
4. Use native TLS and advanced anti-Frida modules only when the base script is insufficient.

## Notes

- A successful hook installation does not prove that the application uses that method.
- Missing optional classes normally mean that the library is absent from the current process or has not yet loaded.
- Flutter signatures and native TLS exports vary by build and may require adjustment.
- The native TLS module cannot reliably enforce hostname-based TLS exclusions.
- Multiprocess applications may require instrumenting each relevant process separately.

## License

Licensed under the Apache License, Version 2.0. See the `LICENSE` file for details.
