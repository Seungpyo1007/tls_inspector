import 'dart:typed_data';

/// Returns the DNS names and IP addresses in the subject alternative name
/// extension of a DER-encoded X.509 certificate, in certificate order.
///
/// Returns an empty list when the certificate has no such extension, and
/// throws a [FormatException] when [der] is not a well-formed certificate.
/// Works on every platform, including the web.
List<String> parseSubjectAltNames(Uint8List der) {
  final certificate = _Tlv.read(der, 0, der.length);
  final tbs = certificate.tag == _sequence
      ? certificate.children(der).firstOrNull
      : null;
  if (tbs == null || tbs.tag != _sequence) {
    throw const FormatException('Not a DER-encoded X.509 certificate.');
  }
  // tbsCertificate ends with [3] EXPLICIT Extensions.
  final wrapper = tbs.children(der).where((field) => field.tag == 0xa3);
  final extensions = wrapper.firstOrNull?.children(der).firstOrNull;
  if (extensions == null) return const <String>[];

  for (final extension in extensions.children(der)) {
    final fields = extension.children(der);
    if (fields.length < 2 || !_isSanOid(der, fields.first)) continue;
    final value = fields.last;
    if (value.tag != _octetString) {
      throw const FormatException('Malformed subjectAltName extension.');
    }
    final names = _Tlv.read(der, value.start, value.end);
    return <String>[
      for (final name in names.children(der))
        if (name.tag == _dnsName)
          String.fromCharCodes(der, name.start, name.end)
        else if (name.tag == _ipAddress)
          _formatIp(Uint8List.sublistView(der, name.start, name.end)),
    ];
  }
  return const <String>[];
}

const _sequence = 0x30;
const _octetString = 0x04;
const _objectIdentifier = 0x06;
// Context-specific, primitive GeneralName choices.
const _dnsName = 0x82;
const _ipAddress = 0x87;
// 2.5.29.17, id-ce-subjectAltName.
const _sanOid = [0x55, 0x1d, 0x11];

bool _isSanOid(Uint8List der, _Tlv field) {
  if (field.tag != _objectIdentifier) return false;
  if (field.end - field.start != _sanOid.length) return false;
  for (var i = 0; i < _sanOid.length; i++) {
    if (der[field.start + i] != _sanOid[i]) return false;
  }
  return true;
}

/// One DER tag-length-value element; [start] and [end] bound its content.
final class _Tlv {
  const _Tlv(this.tag, this.start, this.end);

  /// Reads the element at [offset], which must end by [limit].
  factory _Tlv.read(Uint8List bytes, int offset, int limit) {
    if (offset + 2 > limit) throw const FormatException('Truncated DER.');
    final tag = bytes[offset];
    var length = bytes[offset + 1];
    var start = offset + 2;
    if (length >= 0x80) {
      final count = length & 0x7f;
      if (count == 0 || count > 4 || start + count > limit) {
        throw const FormatException('Unsupported DER length.');
      }
      length = 0;
      for (var i = 0; i < count; i++) {
        length = (length << 8) | bytes[start++];
      }
    }
    if (start + length > limit) throw const FormatException('Truncated DER.');
    return _Tlv(tag, start, start + length);
  }

  final int tag;
  final int start;
  final int end;

  List<_Tlv> children(Uint8List bytes) {
    final children = <_Tlv>[];
    for (var offset = start; offset < end;) {
      final child = _Tlv.read(bytes, offset, end);
      children.add(child);
      offset = child.end;
    }
    return children;
  }
}

/// Formats an IPv4 or IPv6 address, compressing the longest run of zero
/// groups in IPv6 as RFC 5952 recommends.
String _formatIp(Uint8List bytes) {
  if (bytes.length == 4) return bytes.join('.');
  if (bytes.length != 16) {
    return bytes.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join();
  }
  final groups = [
    for (var i = 0; i < 16; i += 2) (bytes[i] << 8) | bytes[i + 1],
  ];
  var runStart = -1;
  var runLength = 1;
  for (var i = 0; i < 8; i++) {
    var j = i;
    while (j < 8 && groups[j] == 0) {
      j++;
    }
    if (j - i > runLength) {
      runStart = i;
      runLength = j - i;
    }
  }
  String hex(Iterable<int> part) =>
      part.map((group) => group.toRadixString(16)).join(':');
  if (runStart < 0) return hex(groups);
  return '${hex(groups.take(runStart))}::'
      '${hex(groups.skip(runStart + runLength))}';
}
