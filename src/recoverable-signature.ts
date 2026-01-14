import { BERTLV } from "./ber-tlv.ts"
import { CryptoUtils } from "./crypto-utils.ts"
import { Ethereum } from "./ethereum.ts"
import { Constants } from "./constants.ts";
import * as secp from '@noble/secp256k1'; 
import { RecoverableSignatureProps } from "./types/recoverable-signature-types.ts";
export class RecoverableSignature {
  publicKey?: Uint8Array;
  recId?: number;
  r?: Uint8Array;
  s?: Uint8Array;
  compressed?: boolean;

  public static toUInt(signedInt: Uint8Array): Uint8Array {
    return (signedInt[0] == 0) ? signedInt.subarray(1) : signedInt;
  }

  constructor(props: RecoverableSignatureProps) {
    if (props.hash && props.tlvData) {
      this.fromTLV(props.hash, props.tlvData);
    } else {
        Object.assign(this, {publicKey: props.publicKey, recId: props.recId, r: props.r, s: props.s, compressed: props.compressed});
    }
  }

  fromTLV(hash: Uint8Array, tlvData: Uint8Array): void {
    let tlv = new BERTLV(tlvData!);
    let props = {} as RecoverableSignatureProps;
    
    tlv.enterConstructed(Constants.TLV_SIGNATURE_TEMPLATE);
    props.publicKey = tlv.readPrimitive(Constants.TLV_PUB_KEY);
    tlv.enterConstructed(Constants.TLV_ECDSA_TEMPLATE);
    props.r = RecoverableSignature.toUInt(tlv.readPrimitive(Constants.TLV_INT));
    props.s = RecoverableSignature.toUInt(tlv.readPrimitive(Constants.TLV_INT));
    props.compressed = false;
    props.recId = this.calculateRecID(hash);

    Object.assign(this, {publicKey: props.publicKey, rectId: props.recId, r: props.r, s: props.s, compressed: props.compressed});
  }

  calculateRecID(hash: Uint8Array): number {
    let recId = -1;

    for (let i = 0; i < 4; i++) {
      let candidate = this.recoverFromSignature(i, hash, this.r!, this.s!, this.compressed!);

      if (CryptoUtils.Uint8ArrayEqual(candidate, this.publicKey!)) {
        recId = i;
        break;
      }
    }

    if (recId == -1) {
      throw new Error("Error: Unrecoverable signature, cannot find recId");
    } else {
        return recId;
    }
  }

  getEthereumAddress(): Uint8Array {
    return Ethereum.toEthereumAddress(this.publicKey!);
  }

  recoverFromSignature(recId: number, hash: Uint8Array, r: Uint8Array, s: Uint8Array, compressed: boolean): Uint8Array {
    let signature = new Uint8Array(this.r!.byteLength + this.s!.byteLength + 1);
    signature.set(r, 0);
    signature.set(s, r.byteLength);
    signature[65] = recId;
    let compressedKey = secp.recoverPublicKey(signature, hash, {prehash: false});

    if (compressed) {
      return compressedKey;
    } else {
      return secp.Point.fromBytes(compressedKey).toBytes(false);
    }
  }
}