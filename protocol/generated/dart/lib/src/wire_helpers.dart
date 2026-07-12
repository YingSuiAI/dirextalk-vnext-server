import 'dart:convert';
import 'dart:typed_data';

/// Unsigned JSON number that remains exact on Dart Web and JavaScript.
final class SafeUint {
  factory SafeUint(int value) {
    if (value < 0 || value > maxValue) {
      throw const FormatException(
        'safe unsigned integer must be between 0 and 2^53 - 1',
      );
    }
    return SafeUint._(value);
  }

  const SafeUint._(this.value);

  static const int maxValue = 9007199254740991;

  final int value;
}

Uint8List decodeSha256(String value) {
  const prefix = 'sha256:';
  if (!value.startsWith(prefix)) {
    throw const FormatException('SHA-256 value has the wrong algorithm');
  }
  return decodeLowerHex(value.substring(prefix.length), expectedBytes: 32);
}

Uint8List decodeEd25519PublicKey(String value) =>
    _decodeEd25519(value, expectedBytes: 32);

Uint8List decodeEd25519Signature(String value) =>
    _decodeEd25519(value, expectedBytes: 64);

Uint8List decodeLowerHex(String value, {required int expectedBytes}) {
  if (value.length != expectedBytes * 2 ||
      !RegExp(r'^[0-9a-f]+$').hasMatch(value)) {
    throw const FormatException('value is not canonical lowercase hex');
  }
  return Uint8List.fromList(<int>[
    for (var index = 0; index < value.length; index += 2)
      int.parse(value.substring(index, index + 2), radix: 16),
  ]);
}

String encodeLowerBase32(List<int> bytes) {
  const alphabet = 'abcdefghijklmnopqrstuvwxyz234567';
  final output = StringBuffer();
  var buffer = 0;
  var bits = 0;
  for (final byte in bytes) {
    buffer = (buffer << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      output.write(alphabet[(buffer >> bits) & 0x1f]);
      buffer &= bits == 0 ? 0 : (1 << bits) - 1;
    }
  }
  if (bits > 0) {
    output.write(alphabet[(buffer << (5 - bits)) & 0x1f]);
  }
  return output.toString();
}

Uint8List _decodeEd25519(String value, {required int expectedBytes}) {
  const prefix = 'ed25519:';
  if (!value.startsWith(prefix)) {
    throw const FormatException('Ed25519 value has the wrong algorithm');
  }
  final encoded = value.substring(prefix.length);
  if (encoded.contains('=') || !RegExp(r'^[A-Za-z0-9_-]+$').hasMatch(encoded)) {
    throw const FormatException('Ed25519 value is not unpadded base64url');
  }
  final padding = '=' * ((4 - encoded.length % 4) % 4);
  final decoded = base64Url.decode('$encoded$padding');
  if (decoded.length != expectedBytes) {
    throw const FormatException('Ed25519 value has the wrong length');
  }
  return decoded;
}
