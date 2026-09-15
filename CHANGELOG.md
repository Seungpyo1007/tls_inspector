## 0.0.2

* Add `TlsCertificateInfo.coversHost`, which matches a host name against the
  subject alternative names, including single-label wildcards.
* Add `TlsCertificateInfo.der` with the DER-encoded certificate.
* Add pub.dev and CI badges to the README.

## 0.0.1

* Initial release.
* `inspectTls` connects to a host, completes a TLS handshake, and returns a
  `TlsCertificateInfo` with subject, issuer, validity dates, subject
  alternative names, SHA-1 fingerprint, PEM, and whether the platform trusted
  the certificate.
* `parseSubjectAltNames` reads DNS names and IP addresses from a DER-encoded
  certificate on every platform, including the web.
* `TlsInspectException` reports `timeout`, `connect_failed`, and
  `handshake_failed`.
