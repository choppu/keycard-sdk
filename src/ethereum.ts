import { keccak_256 } from "@noble/hashes/sha3";
import * as secp256 from '@noble/secp256k1';

export namespace Ethereum {
  export function toEthereumAddress(publicKey: Uint8Array) : Uint8Array {
    if(publicKey.length == 33) {
      publicKey = secp256.Point.fromBytes(publicKey).toBytes(false);
    }
    return keccak_256(publicKey.subarray(1)).subarray(12);
  }
}