@TestOn('vm')
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:tls_inspector/tls_inspector.dart';

// Self-signed fixtures made with OpenSSL, valid 2026-01-01 to 2036-01-01:
// cert.pem has SANs localhost, example.test, 127.0.0.1, and ::1.
const _fixtures = 'test/fixtures';

Uint8List _der(String file) => base64.decode(
  File(
    '$_fixtures/$file',
  ).readAsStringSync().replaceAll(RegExp(r'-----[^-]+-----|\s'), ''),
);

Matcher _throwsCode(String code) =>
    throwsA(isA<TlsInspectException>().having((e) => e.code, 'code', code));

void main() {
  group('parseSubjectAltNames', () {
    test('reads DNS names and IPv4 and IPv6 addresses', () {
      expect(parseSubjectAltNames(_der('cert.pem')), [
        'localhost',
        'example.test',
        '127.0.0.1',
        '::1',
      ]);
    });

    test('returns an empty list without the extension', () {
      expect(parseSubjectAltNames(_der('nosan.pem')), isEmpty);
    });

    test('rejects malformed input', () {
      expect(
        () => parseSubjectAltNames(Uint8List.fromList([0x30, 0x82, 0x10])),
        throwsFormatException,
      );
      expect(
        () => parseSubjectAltNames(Uint8List.fromList([0x04, 0x00])),
        throwsFormatException,
      );
      final der = _der('cert.pem');
      expect(
        () => parseSubjectAltNames(Uint8List.sublistView(der, 0, 100)),
        throwsFormatException,
      );
    });
  });

  group('inspectTls', () {
    test('returns an untrusted self-signed certificate', () async {
      final context = SecurityContext()
        ..useCertificateChain('$_fixtures/cert.pem')
        ..usePrivateKey('$_fixtures/key.pem');
      final server = await SecureServerSocket.bind(
        InternetAddress.loopbackIPv4,
        0,
        context,
      );
      addTearDown(server.close);
      server.listen((socket) => socket.destroy(), onError: (_) {});

      final info = await inspectTls('127.0.0.1', port: server.port);

      expect(info.host, '127.0.0.1');
      expect(info.port, server.port);
      expect(info.trusted, isFalse);
      expect(info.subject, contains('tls-inspector-test'));
      expect(info.issuer, info.subject);
      expect(info.notBefore, DateTime.utc(2026));
      expect(info.notAfter, DateTime.utc(2036));
      expect(info.subjectAltNames, [
        'localhost',
        'example.test',
        '127.0.0.1',
        '::1',
      ]);
      expect(
        info.sha1Fingerprint,
        matches(RegExp(r'^([0-9A-F]{2}:){19}[0-9A-F]{2}$')),
      );
      expect(info.pem, contains('BEGIN CERTIFICATE'));
      expect(info.der, _der('cert.pem'));
      expect(info.coversHost('127.0.0.1'), isTrue);
    });

    test('maps a refused connection to connect_failed', () async {
      final closed = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
      final port = closed.port;
      await closed.close();

      await expectLater(
        inspectTls('127.0.0.1', port: port),
        _throwsCode('connect_failed'),
      );
    });

    test('maps a non-TLS server to handshake_failed', () async {
      final server = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
      addTearDown(server.close);
      server.listen((socket) async {
        socket.write('HTTP/1.1 400 Bad Request\r\n\r\n');
        await socket.close();
      });

      await expectLater(
        inspectTls('127.0.0.1', port: server.port),
        _throwsCode('handshake_failed'),
      );
    });

    test('times out a server that never answers the handshake', () async {
      final held = <Socket>[];
      final server = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
      addTearDown(() async {
        for (final socket in held) {
          socket.destroy();
        }
        await server.close();
      });
      server.listen(held.add);

      await expectLater(
        inspectTls(
          '127.0.0.1',
          port: server.port,
          timeout: const Duration(milliseconds: 300),
        ),
        _throwsCode('timeout'),
      );
    });

    test('validates arguments', () {
      expect(() => inspectTls(' '), throwsArgumentError);
      expect(() => inspectTls('example.com', port: 0), throwsRangeError);
      expect(() => inspectTls('example.com', port: 65536), throwsRangeError);
    });
  });

  test('matches hosts against subject alternative names', () {
    TlsCertificateInfo covering(List<String> names) => TlsCertificateInfo(
      host: 'badssl.com',
      port: 443,
      subject: '/CN=*.badssl.com',
      issuer: '/CN=Example CA',
      notBefore: DateTime.utc(2026),
      notAfter: DateTime.utc(2027),
      subjectAltNames: names,
      sha1Fingerprint: '',
      trusted: true,
      pem: '',
    );
    final info = covering(['*.badssl.com', 'badssl.com', '127.0.0.1', '*.com']);

    expect(info.coversHost('badssl.com'), isTrue);
    expect(info.coversHost('A.BadSSL.com.'), isTrue);
    expect(info.coversHost('a.b.badssl.com'), isFalse);
    expect(info.coversHost('wrong.host.badssl.com'), isFalse);
    expect(info.coversHost('example.com'), isFalse);
    expect(info.coversHost('127.0.0.1'), isTrue);
    expect(info.coversHost('127.0.0.2'), isFalse);
    expect(info.coversHost(' '), isFalse);
    expect(covering([]).coversHost('badssl.com'), isFalse);
    expect(info.der, isEmpty);
  });

  test('computes days until expiry and expiry state', () {
    final info = TlsCertificateInfo(
      host: 'example.com',
      port: 443,
      subject: '/CN=example.com',
      issuer: '/CN=Example CA',
      notBefore: DateTime.utc(2026),
      notAfter: DateTime.utc(2026, 3, 1),
      sha1Fingerprint: '',
      trusted: true,
      pem: '',
    );

    expect(info.daysUntilExpiry(now: DateTime.utc(2026, 2, 19)), 10);
    expect(info.daysUntilExpiry(now: DateTime.utc(2026, 3, 1, 1)), -1);
    expect(info.isExpired(now: DateTime.utc(2026, 2, 28)), isFalse);
    expect(info.isExpired(now: DateTime.utc(2026, 3, 2)), isTrue);
  });
}
