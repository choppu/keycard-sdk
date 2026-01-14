import { randomBytes } from '@noble/hashes/utils';
import * as secp from '@noble/secp256k1';
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
}