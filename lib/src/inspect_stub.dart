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
  throw UnsupportedError(
    'inspectTls needs dart:io, which browsers do not provide.',
  );
}
