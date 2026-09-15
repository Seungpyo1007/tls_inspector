import 'package:tls_inspector/tls_inspector.dart';

/// Prints the certificate of each host given on the command line:
///
///     dart run example/main.dart seungpyo.online expired.badssl.com
Future<void> main(List<String> args) async {
  final hosts = args.isEmpty ? ['seungpyo.online', 'expired.badssl.com'] : args;
  for (final host in hosts) {
    try {
      final certificate = await inspectTls(host);
      print('$host: ${certificate.trusted ? 'trusted' : 'NOT trusted'}');
      print('  subject: ${certificate.subject}');
      print('  issuer:  ${certificate.issuer}');
      print(
        '  expires: ${certificate.notAfter.toIso8601String()}'
        ' (${certificate.daysUntilExpiry()} days)',
      );
      print('  names:   ${certificate.subjectAltNames.join(', ')}');
      print('  covers $host: ${certificate.coversHost(host)}');
      print('  sha1:    ${certificate.sha1Fingerprint}');
    } on TlsInspectException catch (error) {
      print('$host: ${error.code}: $error');
    }
  }
}
