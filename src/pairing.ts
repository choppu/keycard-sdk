import { Base64 } from 'js-base64';
export class Pairing {
  pairingKey: Uint8Array;
  pairingIndex: number;

  constructor(pairingKey: Uint8Array, pairingIndex: number) {
    this.pairingKey = pairingKey;
    this.pairingIndex = pairingIndex;
  }

  static fromBytes(fromByteArray: Uint8Array) : Pairing  {
    return new Pairing(fromByteArray.slice(1), fromByteArray[0]);
  }

  static fromString(base64Str: string) : Pairing {
    let bytes = Base64.toUint8Array(base64Str);
    return this.fromBytes(bytes);
  }

  toByteArray() : Uint8Array {
    let res = new Uint8Array(this.pairingKey.byteLength + 1);
    res[0] = this.pairingIndex;
    res.set(this.pairingKey, 1);
    return res;
  }

  toBase64() : string {
    return Base64.fromUint8Array((this.toByteArray()));
  }
}