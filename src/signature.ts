import { BERTLV } from "./ber-tlv.ts";
import { Constants } from "./constants.ts";
import { CryptoUtils } from "./crypto-utils.ts";
import { RecoverableSignature } from "./recoverable-signature.ts";

const SIGNATURE_SCALAR_BYTES = 32;

export type ParsedSignatureTLV = {
  publicKey: Uint8Array;
  compressedPublicKey: Uint8Array;
  r: Uint8Array;
  s: Uint8Array;
  compactSignature: Uint8Array;
};

export type ParsedRecoverableSignatureTLV = ParsedSignatureTLV & {
  recId: number;
};

export namespace Signature {
  export function normalizeScalar(bytes: Uint8Array): Uint8Array {
    const stripped = bytes[0] === 0x00 ? bytes.slice(1) : bytes;

    if (stripped.length > SIGNATURE_SCALAR_BYTES) {
      throw new Error("Error: Signature scalar is too large");
    }

    if (stripped.length === SIGNATURE_SCALAR_BYTES) {
      return stripped;
    }

    const padded = new Uint8Array(SIGNATURE_SCALAR_BYTES);
    padded.set(stripped, SIGNATURE_SCALAR_BYTES - stripped.length);
    return padded;
  }

  export function parseTLV(tlvData: Uint8Array): ParsedSignatureTLV {
    const tlv = new BERTLV(tlvData);
    tlv.enterConstructed(Constants.TLV_SIGNATURE_TEMPLATE);

    const publicKey = tlv.readPrimitive(Constants.TLV_PUB_KEY);
    tlv.enterConstructed(Constants.TLV_ECDSA_TEMPLATE);

    const r = normalizeScalar(tlv.readPrimitive(Constants.TLV_INT));
    const s = normalizeScalar(tlv.readPrimitive(Constants.TLV_INT));

    const compactSignature = new Uint8Array(2 * SIGNATURE_SCALAR_BYTES);
    compactSignature.set(r, 0);
    compactSignature.set(s, SIGNATURE_SCALAR_BYTES);

    return {
      publicKey,
      compressedPublicKey: CryptoUtils.compressPublicKey(publicKey),
      r,
      s,
      compactSignature,
    };
  }

  export function parseRecoverableTLV(
    hash: Uint8Array,
    tlvData: Uint8Array,
  ): ParsedRecoverableSignatureTLV {
    const parsed = parseTLV(tlvData);
    const recoverable = new RecoverableSignature({ hash, tlvData });

    return {
      ...parsed,
      recId: recoverable.recId!,
    };
  }
}
