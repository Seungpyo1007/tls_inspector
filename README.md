<p align="center">
  <img src="https://raw.githubusercontent.com/Seungpyo1007/tls_inspector/main/assets/tls_inspector-logo.png" alt="tls_inspector logo: a padlock with a magnifying glass" width="128">
</p>

<h1 align="center">tls_inspector</h1>

<p align="center">
  <a href="https://pub.dev/packages/tls_inspector"><img src="https://img.shields.io/pub/v/tls_inspector" alt="pub version"></a>
  <a href="https://pub.dev/packages/tls_inspector/score"><img src="https://img.shields.io/pub/points/tls_inspector" alt="pub points"></a>
  <a href="https://github.com/Seungpyo1007/tls_inspector/actions/workflows/ci.yml"><img src="https://github.com/Seungpyo1007/tls_inspector/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/Seungpyo1007/tls_inspector/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue" alt="MIT license"></a>
</p>

See the TLS certificate a server actually presents: who issued it, when it
expires, which names it covers, and whether your platform trusts it. Useful
for certificate expiry alerts, deployment checks, and debugging HTTPS errors.

```dart
final certificate = await inspectTls('google.com');

print(certificate.issuer);            // /C=US/O=Google Trust Services/CN=WR2
print(certificate.daysUntilExpiry()); // e.g. 58
print(certificate.subjectAltNames);   // [*.google.com, google.com, ...]
print(certificate.trusted);           // true
```

## Platform support

| Platform | `inspectTls` | `parseSubjectAltNames` |
| --- | --- | --- |
| Android, iOS, Windows, macOS, Linux, Dart VM | Yes | Yes |
| Web | No, browsers do not expose raw TLS connections | Yes |

On the web, `inspectTls` throws an `UnsupportedError`. Apps need network
access: the `INTERNET` permission on Android release builds and the
`com.apple.security.network.client` entitlement on macOS.

## Features

- Returns the certificate even when it is expired, self-signed, or issued for
  another host, with `trusted` telling whether the platform accepted it.
- Subject, issuer, validity dates in UTC, days until expiry, SHA-1
  fingerprint, and PEM.
- Subject alternative names (DNS names and IP addresses) parsed from the
  certificate, which `dart:io` does not expose.
- Stable error codes: `timeout`, `connect_failed`, and `handshake_failed`.
- `coversHost` checks a host name against the certificate's names, including
  wildcards, so you can tell a name mismatch from an untrusted chain.
- `der` holds the raw certificate for other fingerprints such as SHA-256.
- No dependencies.

## Installation

```yaml
dependencies:
  tls_inspector: ^0.0.2
```

## Usage

```dart
try {
  final certificate = await inspectTls(
    'example.com',
    port: 443,
    timeout: const Duration(seconds: 5),
  );
  if (!certificate.trusted) {
    print('Untrusted certificate from ${certificate.issuer}');
  } else if (certificate.daysUntilExpiry() < 14) {
    print('Renew soon: ${certificate.notAfter}');
  }
} on TlsInspectException catch (error) {
  print('${error.code}: $error');
}
```

Parse names from a certificate you already have, on any platform:

```dart
final der = base64.decode(
  pem.replaceAll(RegExp(r'-----[^-]+-----|\s'), ''),
);
print(parseSubjectAltNames(der));
```

Tell a name mismatch from an untrusted chain:

```dart
final certificate = await inspectTls('wrong.host.badssl.com');
if (!certificate.trusted && !certificate.coversHost('wrong.host.badssl.com')) {
  print('Issued for ${certificate.subjectAltNames}'); // [*.badssl.com, badssl.com]
}
```

Compute a SHA-256 fingerprint with `package:crypto`:

```dart
import 'package:crypto/crypto.dart';

print(sha256.convert(certificate.der));
```

## Limitations

- Only the server (leaf) certificate is returned. `dart:io` does not expose
  the rest of the chain.
- `trusted` reflects the trust store of the device running the code, so it can
  differ between platforms.
- The SHA-1 fingerprint identifies a certificate; it says nothing about the
  signature algorithm.

## Flutter example

```dart
FutureBuilder<TlsCertificateInfo>(
  future: inspectTls('seungpyo.online'),
  builder: (context, snapshot) {
    final certificate = snapshot.data;
    if (certificate == null) return const LinearProgressIndicator();
    return ListTile(
      leading: Icon(certificate.trusted ? Icons.lock : Icons.lock_open),
      title: Text(certificate.issuer),
      subtitle: Text('Expires in ${certificate.daysUntilExpiry()} days'),
    );
  },
)
```
