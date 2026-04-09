import { sha256 } from "@noble/hashes/sha2";
import { hmac } from "@noble/hashes/hmac";
import * as secp from "@noble/secp256k1";

import { CryptoUtils } from "../src/crypto-utils";
import { Signature } from "../src/signature";

const privateKey = new Uint8Array([
  186, 240, 247, 237, 145, 53, 118, 68,
  96, 251, 38, 229, 65, 202, 162, 134,
  6, 118, 195, 23, 79, 43, 94, 54,
  100, 177, 162, 242, 73, 105, 48, 83,
]);

secp.hashes.sha256 = sha256;
secp.hashes.hmacSha256 = (key, msg) => hmac(sha256, key, msg);

const hash = sha256(new TextEncoder().encode("keycard-signature-test"));
const publicKey = secp.getPublicKey(privateKey, false);
const signature = secp.sign(hash, privateKey, { format: "recovered", prehash: false });
const r = signature.subarray(1, 33);
const s = signature.subarray(33, 65);

function encodeInteger(bytes: Uint8Array, addLeadingZero = false): number[] {
  const normalized = addLeadingZero ? new Uint8Array([0x00, ...bytes]) : bytes;
  return [0x02, normalized.length, ...normalized];
}

function buildSignatureTLV(args?: { addLeadingZeroToR?: boolean; addLeadingZeroToS?: boolean }): Uint8Array {
  const ecdsa = [
    ...encodeInteger(r, args?.addLeadingZeroToR),
    ...encodeInteger(s, args?.addLeadingZeroToS),
  ];

  return new Uint8Array([
    0xa0,
    2 + publicKey.length + 2 + ecdsa.length,
    0x80,
    publicKey.length,
    ...publicKey,
    0x30,
    ecdsa.length,
    ...ecdsa,
  ]);
}

test("Signature.parseTLV returns normalized signature fields", () => {
  const tlv = buildSignatureTLV({ addLeadingZeroToR: true, addLeadingZeroToS: true });
  const parsed = Signature.parseTLV(tlv);

  expect(parsed.publicKey).toEqual(publicKey);
  expect(parsed.compressedPublicKey).toEqual(CryptoUtils.compressPublicKey(publicKey));
  expect(parsed.r).toEqual(r);
  expect(parsed.s).toEqual(s);
  expect(parsed.compactSignature).toEqual(new Uint8Array([...r, ...s]));
});

test("Signature.parseRecoverableTLV returns recId compatible with the signature hash", () => {
  const tlv = buildSignatureTLV();
  const parsed = Signature.parseRecoverableTLV(hash, tlv);

  expect(parsed.recId).toBe(signature[0]);
  expect(parsed.compactSignature).toEqual(new Uint8Array([...r, ...s]));
});

test("Signature.normalizeScalar rejects scalars longer than 32 bytes", () => {
  expect(() => Signature.normalizeScalar(new Uint8Array(33).fill(1))).toThrow(
    "Error: Signature scalar is too large",
  );
});
