import { BERTLV } from "./ber-tlv"
import { CryptoUtils } from "./crypto-utils"
import { Ethereum } from "./ethereum"
import { Constants } from "./constants";

const secp256k1 = require('secp256k1');
export class RecoverableSignature {
  publicKey: Uint8Array;
  recId: number;
  r: Uint8Array;
  s: Uint8Array;
  compressed: boolean;

  toUInt(signedInt: Uint8Array): Uint8Array {
    return (signedInt[0] == 0) ? signedInt.subarray(1) : signedInt;
  }

  constructor(publicKey: Uint8Array, compressed: boolean, r: Uint8Array, s: Uint8Array, recId: number);
  constructor(hash: Uint8Array, tlvData: Uint8Array);

  constructor(arg1: Uint8Array, arg2: Uint8Array | boolean, arg3?: Uint8Array, arg4?: Uint8Array, arg5?: number) {
    if (arg1 instanceof Uint8Array && arg2 instanceof Uint8Array) {
      this.fromTLV(arg1, arg2);
    } else {
      this.publicKey = arg1;
      this.r = arg3;
      this.s = arg4;
      this.compressed = arg2 as boolean;
      this.recId = arg5;
    }
  }

  fromTLV(hash?: Uint8Array, tlvData?: Uint8Array): void {
    let tlv = new BERTLV(tlvData);
    tlv.enterConstructed(Constants.TLV_SIGNATURE_TEMPLATE);
    this.publicKey = tlv.readPrimitive(Constants.TLV_PUB_KEY);
    tlv.enterConstructed(Constants.TLV_ECDSA_TEMPLATE);
    this.r = this.toUInt(tlv.readPrimitive(Constants.TLV_INT));
    this.s = this.toUInt(tlv.readPrimitive(Constants.TLV_INT));
    this.compressed = false;

    this.calculateRecID(hash);
  }

  calculateRecID(hash: Uint8Array): void {
    let recId = -1;

    for (let i = 0; i < 4; i++) {
      let candidate = this.recoverFromSignature(i, hash, this.r, this.s, this.compressed);

      if (CryptoUtils.Uint8ArrayEqual(candidate, this.publicKey)) {
        recId = i;
        this.recId = i;
        break;
      }
    }

    if (recId == -1) {
      throw new Error("Error: Unrecoverable signature, cannot find recId");
    }
  }

  getEthereumAddress(): Uint8Array {
    return Ethereum.toEthereumAddress(this.publicKey);
  }

  recoverFromSignature(recId: number, hash: Uint8Array, r: Uint8Array, s: Uint8Array, compressed: boolean): Uint8Array {
    let signature = new Uint8Array(this.r.byteLength + this.s.byteLength);
    signature.set(r, 0);
    signature.set(s, r.byteLength);

    return secp256k1.ecdsaRecover(signature, recId, hash, compressed);
  }
}