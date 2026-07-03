import { randomBytes } from '@noble/hashes/utils';
import { cbc } from '@noble/ciphers/aes.js';
import * as secp from '@noble/secp256k1';
import { BERTLV } from './ber-tlv.ts';
import { Constants } from './constants.ts';

export namespace CryptoUtils {
  export function wordArrayToByteArray(wordArray: any) : Uint8Array {
    let words = wordArray.words;
    let sigBytes = wordArray.sigBytes;

    let bytes = [];
    for (var i = 0; i < sigBytes; i++) {
      var byte = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
      bytes.push(byte);
    }

    return new Uint8Array(bytes);
  }

  export function stringToUint8Array(str: string) : Uint8Array {
    var result = new Uint8Array(str.length);
    for (var i = 0; i < str.length; i++) {
      result[i] = str.charCodeAt(i);
    }
    return result;
  }

  export function Uint8ArrayEqual(arr1: Uint8Array, arr2: Uint8Array) : boolean {
    return (arr1.byteLength == arr2.byteLength) && (arr1.every(function(el, i) {
      return el === arr2[i];
    }));
  }

  export function getAppVersionString(appVersion: number) : string {
    return (appVersion >> 8) + "." + (appVersion & 0xff);
  }

  export function generateECPrivateKey() {
    return secp.utils.randomSecretKey();
  }

  export function getRandomBytes(size: number) : Uint8Array {
    return randomBytes(size);
  }

  export function checkAllDigits(value: string) : boolean {
    return value.split("").every((c) => '0123456789'.includes(c));
  }

  export function compressPublicKey(pubkey: Uint8Array) : Uint8Array {
    return secp.Point.fromBytes(pubkey).toBytes();
  }

  //Add Iso97971 padding
  export function addIso97971Padding(data: Uint8Array): Uint8Array {
    const blockSize = 16;
    const paddedLength = Math.ceil((data.length + 1) / blockSize) * blockSize;
    const result = new Uint8Array(paddedLength);

    result.set(data);
    result[data.length] = 0x80;

    return result;
  }

  //Remove Iso97971 padding
  export function removeIso97971Padding(data: Uint8Array): Uint8Array {
    let pad = data.length - 1;

    while (pad >= 0 && data[pad] !== 0x80) {
      pad--;
    }

    return data.subarray(0, pad);
  }


  export function aesDecrypt(data: Uint8Array, key: Uint8Array, iv: Uint8Array) : Uint8Array {
    let decData = cbc(key, iv, {disablePadding: true}).decrypt(data);
    return removeIso97971Padding(decData);
  }

  export function aesEncrypt(data: Uint8Array, key: Uint8Array, iv: Uint8Array, noPadding: boolean) {
    let dataToEncrypt = noPadding ? data : addIso97971Padding(data);
    return cbc(key, iv, {disablePadding: true}).encrypt(dataToEncrypt);
  }

  export function constantTimeCompare(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) {
      return false;
    }

    let result = 0;
    for (let i = 0; i < a.length; i++) {
      result |= a[i] ^ b[i];
    }

    return result === 0;
  }

  export function derToCompact(derSignature: Uint8Array): Uint8Array {
    const ber = new BERTLV(derSignature);

    ber.enterConstructed(Constants.TLV_ECDSA_TEMPLATE);

    // Read r and s as raw INTEGER primitives (tag 0x02)
    const r = stripLeadingZero(ber.readPrimitive(0x02));
    const s = stripLeadingZero(ber.readPrimitive(0x02));

    const compact = new Uint8Array(64);
    compact.set(r, 32 - r.length);
    compact.set(s, 32 + 32 - s.length);

    return compact;
  }

  function stripLeadingZero(bytes: Uint8Array): Uint8Array {
    let start = 0;

    while (start < bytes.length - 1 && bytes[start] === 0) start++;
    return bytes.slice(start);
  }
}