import { keccak_256 } from "@noble/hashes/sha3";
import * as secp256 from '@noble/secp256k1';
import { CryptoUtils } from "./crypto-utils.ts";

export namespace Ethereum {
  export function toEthereumAddress(publicKey: Uint8Array) : Uint8Array {
    if(publicKey.length == 33) {
      publicKey = secp256.Point.fromBytes(publicKey).toBytes(false);
    }
    return keccak_256(publicKey.subarray(1)).subarray(12);
  }

  export function encodeEthPersonalMessage(message: string) : Uint8Array {
  const prefixBytes = CryptoUtils.stringToUint8Array('\x19Ethereum Signed Message:\n');
  const messageBytes = CryptoUtils.stringToUint8Array(message);
  const prefixedMessage = new Uint8Array(prefixBytes.byteLength + 1 + messageBytes.byteLength);

  prefixedMessage.set(prefixBytes, 0);
  prefixedMessage[prefixBytes.length] = messageBytes.byteLength;
  prefixedMessage.set(messageBytes, prefixBytes.length + 1);

  return prefixedMessage;
}
}