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
    this.der = const <int>[],
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

  /// The DER-encoded certificate, for computing other fingerprints such as
  /// SHA-256.
  final List<int> der;

  /// Whole days left until [notAfter], rounded down so the value turns
  /// negative as soon as the certificate expires.
  int daysUntilExpiry({DateTime? now}) =>
      (notAfter.difference(now ?? DateTime.now()).inMicroseconds /
              Duration.microsecondsPerDay)
          .floor();

  /// Whether [notAfter] has passed.
  bool isExpired({DateTime? now}) => (now ?? DateTime.now()).isAfter(notAfter);

  /// Whether [subjectAltNames] cover [host], ignoring case and a trailing dot.
  ///
  /// A wildcard such as `*.example.com` covers exactly one more label
  /// (`a.example.com`, not `example.com` or `a.b.example.com`). IP addresses
  /// must match exactly. Like modern clients, the subject common name is not
  /// used.
  bool coversHost(String host) {
    final name = _canonical(host);
    if (name.isEmpty) return false;
    final isAddress = name.contains(':') || RegExp(r'^[\d.]+$').hasMatch(name);
    for (final altName in subjectAltNames) {
      final pattern = _canonical(altName);
      if (pattern == name) return true;
      // Wildcards need at least two labels after `*.`, so `*.com` covers
      // nothing.
      if (isAddress || !pattern.startsWith('*.')) continue;
      if (!pattern.substring(2).contains('.')) continue;
      final dot = name.indexOf('.');
      if (dot > 0 && name.substring(dot) == pattern.substring(1)) return true;
    }
    return false;
  }
}

String _canonical(String name) =>
    name.trim().toLowerCase().replaceFirst(RegExp(r'\.$'), '');

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
