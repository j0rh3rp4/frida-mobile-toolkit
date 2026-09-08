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
- Optional WebView and Flutter support

### TLS Mode

Set `CONFIG.tlsMode` near the beginning of the script:

```javascript
/*
 * TLS modes:
 *   GLOBAL   - Bypass TLS pinning for every supported connection.
 *   B2C_SAFE - Bypass supported TLS pinning except Microsoft Entra ID,
 *              MSAL, and Azure AD B2C authentication hosts.
 */
tlsMode: 'GLOBAL',
```

Use `GLOBAL` for normal testing. Use `B2C_SAFE` when a global permissive TrustManager breaks a Microsoft authentication flow.

## Optional Modules

Load optional modules alongside the main script with additional `-l` arguments:

- `module-rootbeer.js`: Directly hooks common RootBeer detection methods.
- `module-cronet.js`: Disables configured Cronet public-key pins, enables local trust-anchor bypass, and disables QUIC.
- `module-late-loader.js`: Reports security-related classes loaded after application startup.
- `module-native-tls.js`: Adds conservative hooks for common native OpenSSL and BoringSSL verification functions.
- `module-antifrida-advanced.js`: Adds extra Frida-marker filtering and native anti-Frida reconnaissance.

## Usage

Run the main script:

```bash
frida -U -f com.example.app \
  -l mobile-universal.js
```

Load optional modules when required:

```bash
frida -U -f com.example.app \
  -l mobile-universal.js \
  -l module-rootbeer.js \
  -l module-cronet.js
```

## Recommended Workflow

1. Start with `mobile-universal.js` using `tlsMode: 'GLOBAL'`.
2. Change the mode to `B2C_SAFE` if Microsoft authentication fails with the global bypass.
3. Add RootBeer or Cronet modules only when those technologies are present.
4. Use the late-loader module when relevant classes are loaded dynamically.
5. Use native TLS and advanced anti-Frida modules only when the base script is insufficient.

## Notes

- A successful hook installation does not prove that the application uses that method.
- `ClassNotFoundException` for optional libraries normally means that the library is absent from the current process or class loader.
- Flutter signatures and native TLS exports vary by build and may require adjustment.
- The native TLS module cannot reliably enforce hostname-based B2C exclusions. Avoid combining it with `B2C_SAFE` unless the authentication traffic uses a different TLS stack.
- Multiprocess applications may require instrumenting each relevant process separately.

## License

Licensed under the Apache License, Version 2.0.
See the [LICENSE](LICENSEdetails.
