/// A server certificate as presented during a TLS handshake.
class TlsCertificateInfo {
  /// Creates certificate details.
  const TlsCertificateInfo({
    required this.host,
    required this.port,
    required this.subject,
    required this.issuer,
    required this.notBefore,
    required this.notAfter,
    this.subjectAltNames = const <String>[],
    required this.sha1Fingerprint,
    required this.trusted,
    required this.pem,
  });

  /// Host name or address that was connected to.
  final String host;

  /// Port that was connected to.
  final int port;

  /// Subject distinguished name, such as `/CN=example.com`.
  final String subject;

  /// Issuer distinguished name.
  final String issuer;

  /// Start of the validity period, in UTC.
  final DateTime notBefore;

  /// End of the validity period, in UTC.
  final DateTime notAfter;

  /// DNS names and IP addresses the certificate covers.
  final List<String> subjectAltNames;

  /// SHA-1 fingerprint as uppercase hex pairs separated by colons.
  final String sha1Fingerprint;

  /// Whether the platform trusted the certificate chain for [host].
  final bool trusted;

  /// The certificate in PEM format.
  final String pem;

  /// Whole days left until [notAfter], rounded down so the value turns
  /// negative as soon as the certificate expires.
  int daysUntilExpiry({DateTime? now}) =>
      (notAfter.difference(now ?? DateTime.now()).inMicroseconds /
              Duration.microsecondsPerDay)
          .floor();

  /// Whether [notAfter] has passed.
  bool isExpired({DateTime? now}) => (now ?? DateTime.now()).isAfter(notAfter);
}

/// TLS inspection failure.
class TlsInspectException implements Exception {
  /// Creates a failure.
  const TlsInspectException(this.message, {required this.code});

  /// Safe error description.
  final String message;

  /// Stable error code: `timeout`, `connect_failed`, or `handshake_failed`.
  final String code;

  @override
  String toString() => message;
}
