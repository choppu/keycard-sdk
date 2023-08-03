const secp256k1 = require("secp256k1");

declare global {
  interface Window{
     msCrypto: Crypto;
  }
}

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
    while (true) {
      let privKey = getRandomBytes(32);
      if (secp256k1.privateKeyVerify(privKey)) return privKey;
    }
  }

  export function getRandomBytes(size: number) : Uint8Array {
    if ((typeof window !== 'undefined') && (window.crypto || window.msCrypto)) {
      let crypto = window.crypto || window.msCrypto;
      let a = new Uint8Array(size);
      crypto.getRandomValues(a);
      return a;
    } else {
      let crypto = require("crypto");
      return crypto.randomBytes(size);
    }
  }

  export function checkAllDigits(value: string) : boolean {
    return value.split("").every((c) => '0123456789'.includes(c));
  }

  export function compressPublicKey(pubkey: Uint8Array) : Uint8Array {
    return secp256k1.publicKeyConvert(pubkey, true, new Uint8Array(33));
  }
}