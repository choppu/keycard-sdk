import { BERTLV, TLV_INT } from "./ber-tlv"
import { TLV_PUB_KEY } from "./application-info"
import { CryptoUtils } from "./crypto-utils"
import { Ethereum } from "./ethereum"

const secp256k1 = require('secp256k1');

const TLV_SIGNATURE_TEMPLATE = 0xa0;
const TLV_ECDSA_TEMPLATE = 0x30;

export class RecoverableSignature {
  publicKey: Uint8Array;
  recId: number;
  r: Uint8Array;
  s: Uint8Array;

  toUInt(signedInt: Uint8Array) : Uint8Array {
    return (signedInt[0] == 0) ? signedInt.subarray(1) : signedInt;
  }

  constructor(hash: Uint8Array, tlvData: Uint8Array) {
    let tlv = new BERTLV(tlvData);
    tlv.enterConstructed(TLV_SIGNATURE_TEMPLATE);
    this.publicKey = tlv.readPrimitive(TLV_PUB_KEY);
    tlv.enterConstructed(TLV_ECDSA_TEMPLATE);
    this.r = this.toUInt(tlv.readPrimitive(TLV_INT));
    this.s = this.toUInt(tlv.readPrimitive(TLV_INT));

    let recId = -1;

    for (let i = 0; i < 4; i++) {
      let signature = new Uint8Array(this.r.byteLength + this.s.byteLength);
      signature.set(this.r, 0);
      signature.set(this.s, this.r.byteLength);

      let candidate = secp256k1.ecdsaRecover(signature, i, hash, false);

      if (CryptoUtils.Uint8ArrayEqual(candidate, this.publicKey)) {
        recId = i;
        this.recId = i;
        break;
      }

      if (recId == -1) {
        throw new Error("Error: Unrecoverable signature, cannot find recId");
      }
    }
  }

  getEthereumAddress() : Uint8Array {
    return Ethereum.toEthereumAddress(this.publicKey);
  }
}