import { AESCCM } from "../src/aes-ccm";
import { CryptoUtils } from "../src/crypto-utils";

function bytesFromArray(arr: number[]): Uint8Array {
  return new Uint8Array(arr);
}

function hexToBytes(hex: string): Uint8Array {
  const bytes: number[] = [];
  for (let i = 0; i < hex.length; i += 2) {
    bytes.push(parseInt(hex.substring(i, i + 2), 16));
  }
  return bytesFromArray(bytes);
}

const KEY_256 = hexToBytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
const NONCE = hexToBytes("101112131415161718191a1b1c");
const MESSAGE = CryptoUtils.stringToUint8Array("Hello world");
const RESULT = new Uint8Array([
  0x55, 0xd7, 0x20,0x84, 0xb8, 0x8f, 0x01, 0x17, 0x15,
   0x4c, 0xf3, 0x87, 0x50, 0x3d, 0xc7, 0x46, 0x5b, 0x8a, 0xa1
]);

// ---- Encrypt/Decrypt Roundtrip Tests ----

describe("AESCCM encrypt/decrypt roundtrip", () => {
  test("empty plaintext", () => {
    const aes = new AESCCM(KEY_256);
    const plaintext = MESSAGE;
    const encrypted = aes.encrypt(plaintext, NONCE);
    expect(encrypted).toEqual(RESULT);
  });

  test("single byte plaintext", () => {
    const aes = new AESCCM(KEY_256);
    const decrypted = aes.decrypt(RESULT, NONCE);
    expect(decrypted).toEqual(MESSAGE);
  });
});