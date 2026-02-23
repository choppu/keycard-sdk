export type RecoverableSignatureProps = {
  hash?: Uint8Array,
  tlvData?: Uint8Array,
  publicKey?: Uint8Array;
  recId?: number;
  r?: Uint8Array;
  s?: Uint8Array;
  compressed?: boolean;
}