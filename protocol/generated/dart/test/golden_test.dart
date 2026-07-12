import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:dirextalk_protocol_conformance/dtx_protocol.dart';
import 'package:test/test.dart';

void main() {
  test('public IDs match the independent domain-separated vector', () {
    final vector = _readVector('public-ids.json');
    final publicKey = decodeLowerHex(
      vector['ed25519_public_key_hex']! as String,
      expectedBytes: 32,
    );

    expect(
      _publicId('dtxi1', 'dirextalk.identity.v1\u0000', publicKey),
      vector['identity_id'],
    );
    expect(
      _publicId('dtxc1', 'dirextalk.channel.v1\u0000', publicKey),
      vector['channel_id'],
    );
    expect(
      _publicId('dtxa1', 'dirextalk.agent.v1\u0000', publicKey),
      vector['agent_id'],
    );
  });

  test('plan body bytes and domain-separated hash match Rust golden', () {
    final vector = _readVector('plan-hash.json');
    final body = vector['body']! as Map<String, Object?>;
    final resources = body['resources']! as List<Object?>;
    final cost = body['max_cost']! as Map<String, Object?>;
    final canonical = <int, Object?>{
      1: body['job_id'],
      2: body['revision'],
      3: decodeLowerHex(
        body['objective_hash_hex']! as String,
        expectedBytes: 32,
      ),
      4: body['region'],
      5: <Object?>[
        for (final resourceValue in resources)
          _planResource(resourceValue as Map<String, Object?>),
      ],
      6: <int, Object?>{1: cost['currency'], 2: cost['minor_units']},
      7: body['max_runtime_ms'],
      8: body['artifact_policy'],
      9: body['verification_policy'],
    };
    final encoded = CanonicalCbor.encode(canonical);

    expect(_hex(encoded), vector['canonical_cbor_hex']);
    expect(
      'sha256:${_hex(_hash('dirextalk.job-plan.v1\u0000', encoded))}',
      vector['plan_hash'],
    );
  });

  test(
    'generated event payload and both integrity modes match Rust golden',
    () {
      final vector = _readVector('event-envelope.json');
      final payloadJson = vector['payload']! as Map<String, Object?>;
      final payload = AgentInstallationChangedV1(
        installationId: payloadJson['installation_id']! as String,
        descriptorHash: payloadJson['descriptor_hash']! as String,
        state: payloadJson['state']! as String,
        policyRevision: SafeUint(payloadJson['policy_revision']! as int),
      );
      final unsigned = <int, Object?>{
        1: <int, Object?>{1: 1, 2: 0},
        2: <int, Object?>{1: 1, 2: 0},
        3: vector['event_id'],
        4: vector['tenant_id'],
        5: vector['aggregate_type'],
        6: vector['aggregate_id'],
        7: vector['aggregate_revision'],
        8: vector['stream_sequence'],
        9: vector['occurred_at'],
        10: vector['schema_version'],
        11: vector['event_type'],
        12: vector['required_reader_capability'],
        13: payload.toCanonicalMap(),
      };
      final unsignedBytes = CanonicalCbor.encode(unsigned);
      final digest = _hash('dirextalk.event.v1\u0000', unsignedBytes);
      final hashOnly = <int, Object?>{
        ...unsigned,
        14: <int, Object?>{1: 'sha256', 2: digest},
      };
      final signed = <int, Object?>{
        ...unsigned,
        14: <int, Object?>{
          1: 'ed25519',
          2: digest,
          3: decodeEd25519PublicKey(vector['signer_public_key']! as String),
          4: decodeEd25519Signature(vector['signature']! as String),
        },
      };

      expect(_hex(unsignedBytes), vector['unsigned_cbor_hex']);
      expect('sha256:${_hex(digest)}', vector['event_digest']);
      expect(
        _hex(CanonicalCbor.encode(hashOnly)),
        vector['hash_only_cbor_hex'],
      );
      expect(_hex(CanonicalCbor.encode(signed)), vector['signed_cbor_hex']);
      expect(eventRegistry.length, 17);
    },
  );

  test('API error CBOR and generated error registry match Rust', () {
    final vector = _readVector('api-errors.json');
    final error = vector['error']! as Map<String, Object?>;
    final canonical = <int, Object?>{
      1: error['code'],
      2: error['message'],
      3: error['request_id'],
      4: error['retryable'],
      5: error['details'],
    };

    expect(_hex(CanonicalCbor.encode(canonical)), vector['canonical_cbor_hex']);
    expect(KnownApiErrorCode.values.length, 25);
    expect(
      KnownApiErrorCode.planRevisionConflict.wireCode,
      'PLAN_REVISION_CONFLICT',
    );
  });

  test(
    'canonical writer sorts encoded keys and preserves semantic differences',
    () {
      final sorted = CanonicalCbor.encode(<Object?, Object?>{
        false: null,
        <Object?>[-1]: null,
        'aa': null,
        100: null,
        <Object?>[100]: null,
        -1: null,
        'z': null,
        10: null,
      });

      expect(_hex(sorted), 'a80af61864f620f6617af6626161f6811864f68120f6f4f6');
      expect(
        CanonicalCbor.encode(<int, Object?>{}),
        isNot(CanonicalCbor.encode(<int, Object?>{1: null})),
      );
      expect(CanonicalCbor.encode('é'), isNot(CanonicalCbor.encode('e\u0301')));
      expect(() => CanonicalCbor.encode(1.5), throwsFormatException);
    },
  );

  test('map key sorting obeys the shared encoded byte budget', () {
    final oversizedPendingKeys = <Object?, Object?>{
      for (var index = 0; index < 4096; index += 1) Uint8List(300): null,
    };

    expect(
      () => CanonicalCbor.encode(oversizedPendingKeys),
      throwsA(
        isA<FormatException>().having(
          (error) => error.message,
          'message',
          contains('byte limit'),
        ),
      ),
    );
  });

  test('safe uint accepts the JSON/Web exact boundary only', () {
    const maximum = 9007199254740991;

    expect(SafeUint(maximum).value, maximum);
    expect(() => SafeUint(maximum + 1), throwsFormatException);
    expect(() => SafeUint(-1), throwsFormatException);
  });

  test('BigInt covers the generic canonical CBOR integer boundaries', () {
    final maximumUnsigned = BigInt.parse('18446744073709551615');
    final minimumSigned = BigInt.parse('-9223372036854775808');

    expect(_hex(CanonicalCbor.encode(maximumUnsigned)), '1bffffffffffffffff');
    expect(_hex(CanonicalCbor.encode(minimumSigned)), '3b7fffffffffffffff');
    expect(
      () => CanonicalCbor.encode(maximumUnsigned + BigInt.one),
      throwsFormatException,
    );
    expect(
      () => CanonicalCbor.encode(minimumSigned - BigInt.one),
      throwsFormatException,
    );
  });

  test('map keys consume the same canonical depth budget as values', () {
    Object? nestedKey(int containerCount) {
      Object? value = 0;
      for (var index = 0; index < containerCount; index += 1) {
        value = <Object?>[value];
      }
      return value;
    }

    expect(
      () => CanonicalCbor.encode(<Object?, Object?>{nestedKey(31): null}),
      returnsNormally,
    );
    expect(
      () => CanonicalCbor.encode(<Object?, Object?>{nestedKey(32): null}),
      throwsFormatException,
    );
  });

  test('nested map keys consume the shared canonical item budget', () {
    List<Object?> itemBudgetKey(int finalLength) => <Object?>[
      for (var index = 0; index < 16; index += 1)
        List<Object?>.filled(index == 15 ? finalLength : 4096, null),
    ];

    expect(
      () => CanonicalCbor.encode(<Object?, Object?>{itemBudgetKey(4077): null}),
      returnsNormally,
    );
    expect(
      () => CanonicalCbor.encode(<Object?, Object?>{itemBudgetKey(4078): null}),
      throwsFormatException,
    );
  });
}

Map<String, Object?> _readVector(String name) {
  final source = File('../../test-vectors/v1/$name').readAsStringSync();
  return (jsonDecode(source)! as Map<String, Object?>);
}

Map<int, Object?> _planResource(Map<String, Object?> resource) =>
    <int, Object?>{
      1: resource['logical_name'],
      2: resource['lifecycle'],
      3: resource['kind'],
    };

String _publicId(String prefix, String domain, List<int> key) =>
    '$prefix${encodeLowerBase32(_hash(domain, key))}';

Uint8List _hash(String domain, List<int> value) => Uint8List.fromList(
  sha256.convert(<int>[...utf8.encode(domain), ...value]).bytes,
);

String _hex(List<int> bytes) =>
    bytes.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join();
