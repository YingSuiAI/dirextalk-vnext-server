import 'package:dirextalk_protocol_conformance/dtx_protocol.dart';

void main() {
  const maximumSafeUint = 9007199254740991;
  if (SafeUint(maximumSafeUint).value != maximumSafeUint) {
    throw StateError('SafeUint changed the Web-exact maximum');
  }

  var rejectedUnsafeUint = false;
  try {
    SafeUint(maximumSafeUint + 1);
  } on FormatException {
    rejectedUnsafeUint = true;
  }
  if (!rejectedUnsafeUint) {
    throw StateError('SafeUint accepted 2^53');
  }

  final encoded = CanonicalCbor.encode(BigInt.parse('18446744073709551615'));
  final hex = encoded
      .map((byte) => byte.toRadixString(16).padLeft(2, '0'))
      .join();
  if (hex != '1bffffffffffffffff') {
    throw StateError('unexpected uint64 maximum CBOR: $hex');
  }

  print('web conformance smoke passed');
}
