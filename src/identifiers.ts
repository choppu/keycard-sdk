import { CryptoUtils } from "./crypto-utils";

export namespace Identifiers {
  export const CASH_AID = CryptoUtils.stringToUint8Array("A000000804000103");
  export const CASH_INSTANCE_AID = CryptoUtils.stringToUint8Array("A00000080400010301");

  export const IDENT_AID = CryptoUtils.stringToUint8Array("A000000804000104");
  export const IDENT_INSTANCE_AID = CryptoUtils.stringToUint8Array("A00000080400010401");
}