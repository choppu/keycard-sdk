import { CryptoUtils } from "./crypto-utils";

export namespace GlobalPlatformCrypto {
  export function appendDESPadding(data: Uint8Array) : Uint8Array {
    let paddingLength = 8 - (data.byteLength % 8);
    let paddedData = new Uint8Array(data.byteLength + paddingLength);
    paddedData.set(data, 0);
    paddedData[data.byteLength] = 0x80;
    return paddedData;
  }

  export function ecb3des(key: Uint8Array, data: Uint8Array) : Uint8Array {
    return;
  }

  export function kcv3des(key: Uint8Array) : Uint8Array {
    return;
  }

  export function mac3des(key: Uint8Array, data: Uint8Array, iv: Uint8Array) : Uint8Array {
    return;
  }

  export function encryptICV(macKeyData: Uint8Array, mac: Uint8Array) : Uint8Array {
    return;
  }

  export function macFull3des(key: Uint8Array, data: Uint8Array, iv: Uint8Array) : Uint8Array {
    return;
  }

  export function verifyCryptogram(key: Uint8Array, hostChallenge: Uint8Array, cardChallenge: Uint8Array, cardCryptogram: Uint8Array) : boolean {
    let data = new Uint8Array(hostChallenge.byteLength + cardChallenge.byteLength);
    data.set(hostChallenge, 0);
    data.set(cardChallenge, hostChallenge.byteLength);

    let calculated = mac3des(key, appendDESPadding(data), new Uint8Array(8));

    return CryptoUtils.Uint8ArrayEqual(calculated , cardCryptogram);
  }

  export function deriveSCP02SessionKey(scp02Key: Uint8Array, seq: Uint8Array, derivationPurpose: Uint8Array) : Uint8Array {
    return;
  }

  
}