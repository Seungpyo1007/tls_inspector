/// Inspects the TLS certificate a server presents, and parses subject
/// alternative names from DER-encoded X.509 certificates.
library;

export 'src/der.dart' show parseSubjectAltNames;
export 'src/inspect_stub.dart' if (dart.library.io) 'src/inspect_io.dart';
export 'src/tls_certificate_info.dart';
