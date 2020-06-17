const CryptoJS = require("crypto-js");
import { CryptoUtils } from "./crypto-utils";

export class Pairing {
  pairingKey: Uint8Array;
  pairingIndex: number;

  constructor(pairingKey: Uint8Array, pairingIndex: number) {
    this.pairingKey = new Uint8Array(pairingKey);
    this.pairingIndex = pairingIndex;
  }

  static fromBytes(fromByteArray: Uint8Array) : Pairing  {
    return new Pairing(fromByteArray.slice(1), fromByteArray[0]);
  }

  static fromString(base64Str: string) : Pairing {
    let wordArr = CryptoJS.enc.Base64.parse(base64Str);
    let bytes = CryptoUtils.wordArrayToByteArray(wordArr);
    return this.fromBytes(bytes);
  }

  toByteArray() : Uint8Array {
    let res = new Uint8Array(this.pairingKey.byteLength + 1);
    res[0] = this.pairingIndex;
    res.set(this.pairingKey, 1);
    return res;
  }

  toBase64() : string {
    let wordArray = CryptoJS.lib.WordArray.create(this.toByteArray());
    return CryptoJS.enc.Base64.stringify(wordArray);
  }
}