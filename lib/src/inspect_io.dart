import 'dart:async';
import 'dart:io';

import 'der.dart';
import 'tls_certificate_info.dart';

/// Connects to [host] on [port], completes a TLS handshake, and returns the
/// certificate the server presents.
///
/// The certificate is returned even when it is expired, self-signed, or issued
/// for another name; [TlsCertificateInfo.trusted] tells whether the platform
/// accepted it. Throws a [TlsInspectException] when the connection or
/// handshake fails or takes longer than [timeout].
///
/// Not available on the web, where it throws an [UnsupportedError].
Future<TlsCertificateInfo> inspectTls(
  String host, {
  int port = 443,
  Duration timeout = const Duration(seconds: 10),
}) async {
  final name = host.trim();
  if (name.isEmpty) {
    throw ArgumentError.value(host, 'host', 'Must not be empty.');
  }
  RangeError.checkValueInInterval(port, 1, 65535, 'port');

  var trusted = true;
  final connecting = SecureSocket.connect(
    name,
    port,
    onBadCertificate: (_) {
      trusted = false;
      return true;
    },
  );
  final SecureSocket socket;
  try {
    socket = await connecting.timeout(
      timeout,
      onTimeout: () {
        // The handshake can still finish later; close that socket then.
        unawaited(connecting.then((late) => late.destroy(), onError: (_) {}));
        throw TimeoutException(null, timeout);
      },
    );
  } on TimeoutException {
    throw TlsInspectException(
      'TLS connection to $name:$port timed out.',
      code: 'timeout',
    );
  } on SocketException catch (error) {
    throw TlsInspectException(
      'Could not connect to $name:$port: ${error.message}',
      code: 'connect_failed',
    );
  } on TlsException catch (error) {
    throw TlsInspectException(
      'TLS handshake with $name:$port failed: ${error.message}',
      code: 'handshake_failed',
    );
  }

  final certificate = socket.peerCertificate;
  socket.destroy();
  if (certificate == null) {
    throw TlsInspectException(
      '$name:$port sent no certificate.',
      code: 'handshake_failed',
    );
  }

  List<String> altNames;
  try {
    altNames = parseSubjectAltNames(certificate.der);
  } on FormatException {
    // The platform accepted the certificate; an extension this parser does
    // not understand should not hide the rest of the details.
    altNames = const <String>[];
  }

  return TlsCertificateInfo(
    host: name,
    port: port,
    subject: certificate.subject,
    issuer: certificate.issuer,
    notBefore: certificate.startValidity.toUtc(),
    notAfter: certificate.endValidity.toUtc(),
    subjectAltNames: altNames,
    sha1Fingerprint: certificate.sha1
        .map((byte) => byte.toRadixString(16).padLeft(2, '0').toUpperCase())
        .join(':'),
    trusted: trusted,
    pem: certificate.pem,
  );
}
