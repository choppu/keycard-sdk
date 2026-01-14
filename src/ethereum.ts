import { keccak_256 } from "@noble/hashes/sha3";

export namespace Ethereum {
  export function toEthereumAddress(publicKey: Uint8Array) : Uint8Array {
    return keccak_256(publicKey.subarray(1)).subarray(12);
  }
}