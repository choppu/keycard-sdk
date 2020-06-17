import { CryptoUtils } from "./crypto-utils"
const CryptoJS = require('crypto-js');

export namespace Ethereum {
  export function toEthereumAddress(publicKey: Uint8Array) : Uint8Array {
    let publicKeyWordArr = CryptoJS.lib.WordArray.create(publicKey.subarray(1));
    let hash = CryptoJS.SHA3(publicKeyWordArr, { outputLength: 256 });
    let address = CryptoUtils.wordArrayToByteArray(hash);

    return address.subarray(12);
  }
}