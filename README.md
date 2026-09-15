# tls_inspector

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
- No dependencies.

## Installation

```yaml
dependencies:
  tls_inspector: ^0.0.1
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
