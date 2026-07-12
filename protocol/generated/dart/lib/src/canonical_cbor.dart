import 'dart:convert';
import 'dart:typed_data';

final class CanonicalCbor {
  static const _maxBytes = 1024 * 1024;
  static const _maxDepth = 32;
  static const _maxEntries = 4096;
  static const _maxItems = 65536;
  static final _maxUnsigned = BigInt.parse('18446744073709551615');
  static final _minSigned = BigInt.parse('-9223372036854775808');

  static Uint8List encode(Object? value) => _encodeAtDepth(value, 0);

  static Uint8List _encodeAtDepth(Object? value, int depth) {
    final encoder = _CanonicalEncoder();
    encoder.encode(value, depth);
    return encoder.takeBytes();
  }
}

final class _CanonicalEncoder {
  final BytesBuilder _output = BytesBuilder(copy: false);
  var _items = 0;

  Uint8List takeBytes() => _output.takeBytes();

  int get itemCount => _items;

  void encode(Object? value, int depth) {
    if (depth > CanonicalCbor._maxDepth) {
      throw const FormatException('canonical CBOR depth limit exceeded');
    }
    _chargeItems(1);
    if (value == null) {
      _write(<int>[0xf6]);
    } else if (value is bool) {
      _write(<int>[value ? 0xf5 : 0xf4]);
    } else if (value is int) {
      _encodeInteger(BigInt.from(value));
    } else if (value is BigInt) {
      _encodeInteger(value);
    } else if (value is Uint8List) {
      _writeHead(2, BigInt.from(value.length));
      _write(value);
    } else if (value is String) {
      final bytes = utf8.encode(value);
      _writeHead(3, BigInt.from(bytes.length));
      _write(bytes);
    } else if (value is List<Object?>) {
      _checkEntries(value.length);
      _writeHead(4, BigInt.from(value.length));
      for (final item in value) {
        encode(item, depth + 1);
      }
    } else if (value is Map<Object?, Object?>) {
      _encodeMap(value, depth);
    } else {
      throw FormatException(
        'unsupported canonical CBOR value: ${value.runtimeType}',
      );
    }
  }

  void _encodeMap(Map<Object?, Object?> value, int depth) {
    _checkEntries(value.length);
    final entries = <_EncodedEntry>[];
    var pendingKeyBytes = 0;
    for (final entry in value.entries) {
      final keyEncoder = _CanonicalEncoder();
      keyEncoder.encode(entry.key, depth + 1);
      _chargeItems(keyEncoder.itemCount);
      final encodedKey = keyEncoder.takeBytes();
      pendingKeyBytes += encodedKey.length;
      if (_output.length + pendingKeyBytes > CanonicalCbor._maxBytes) {
        throw const FormatException('canonical CBOR byte limit exceeded');
      }
      entries.add(_EncodedEntry(encodedKey, entry.value));
    }
    entries.sort((left, right) => _compareBytes(left.key, right.key));
    for (var index = 1; index < entries.length; index += 1) {
      if (_compareBytes(entries[index - 1].key, entries[index].key) == 0) {
        throw const FormatException('duplicate canonical CBOR map key');
      }
    }
    _writeHead(5, BigInt.from(entries.length));
    for (final entry in entries) {
      _write(entry.key);
      encode(entry.value, depth + 1);
    }
  }

  void _encodeInteger(BigInt value) {
    if (value >= BigInt.zero) {
      _writeHead(0, value);
    } else {
      if (value < CanonicalCbor._minSigned) {
        throw const FormatException(
          'canonical CBOR negative integer is outside int64',
        );
      }
      _writeHead(1, -BigInt.one - value);
    }
  }

  void _checkEntries(int length) {
    if (length > CanonicalCbor._maxEntries) {
      throw const FormatException('canonical CBOR container limit exceeded');
    }
  }

  void _chargeItems(int count) {
    _items += count;
    if (_items > CanonicalCbor._maxItems) {
      throw const FormatException('canonical CBOR item limit exceeded');
    }
  }

  void _writeHead(int major, BigInt argument) {
    if (argument < BigInt.zero || argument > CanonicalCbor._maxUnsigned) {
      throw const FormatException('canonical CBOR integer is outside uint64');
    }
    final marker = major << 5;
    if (argument < BigInt.from(24)) {
      _write(<int>[marker | argument.toInt()]);
    } else if (argument <= BigInt.from(0xff)) {
      _write(<int>[marker | 0x18, argument.toInt()]);
    } else if (argument <= BigInt.from(0xffff)) {
      _write(<int>[marker | 0x19, (argument >> 8).toInt(), argument.toInt()]);
    } else if (argument <= BigInt.from(0xffffffff)) {
      _write(<int>[
        marker | 0x1a,
        (argument >> 24).toInt(),
        (argument >> 16).toInt(),
        (argument >> 8).toInt(),
        argument.toInt(),
      ]);
    } else {
      _write(<int>[
        marker | 0x1b,
        _lowByte(argument >> 56),
        _lowByte(argument >> 48),
        _lowByte(argument >> 40),
        _lowByte(argument >> 32),
        _lowByte(argument >> 24),
        _lowByte(argument >> 16),
        _lowByte(argument >> 8),
        _lowByte(argument),
      ]);
    }
  }

  void _write(List<int> bytes) {
    if (_output.length + bytes.length > CanonicalCbor._maxBytes) {
      throw const FormatException('canonical CBOR byte limit exceeded');
    }
    _output.add(bytes.map((byte) => byte & 0xff).toList(growable: false));
  }
}

int _lowByte(BigInt value) => (value & BigInt.from(0xff)).toInt();

final class _EncodedEntry {
  const _EncodedEntry(this.key, this.value);

  final Uint8List key;
  final Object? value;
}

int _compareBytes(List<int> left, List<int> right) {
  final sharedLength = left.length < right.length ? left.length : right.length;
  for (var index = 0; index < sharedLength; index += 1) {
    final difference = left[index] - right[index];
    if (difference != 0) {
      return difference;
    }
  }
  return left.length - right.length;
}
