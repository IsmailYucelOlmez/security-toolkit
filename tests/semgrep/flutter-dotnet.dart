// ruleid: dart-hardcoded-api-key
const apiKey = "abcdefghijklmnopqrstuvwx";
// ok: dart-hardcoded-api-key
const title = "abcdefghijklmnopqrstuvwx";

Future<void> save(p, token) async {
  // ruleid: dart-secret-in-shared-preferences
  await p.setString('auth_token', token);
  // ok: dart-secret-in-shared-preferences
  await p.setString('theme', token);
}

void cert(h) {
  // ruleid: dart-bad-certificate-callback
  h.badCertificateCallback = (cert, host, port) => true;
  // ok: dart-bad-certificate-callback
  h.badCertificateCallback = (cert, host, port) => false;
}

// ruleid: dart-cleartext-http
final a = Uri.parse("http://api.ornek.test/login");
// ok: dart-cleartext-http
final b = Uri.parse("http://localhost:8000/");
// ok: dart-cleartext-http
final c = Uri.parse("https://api.ornek.test/login");
