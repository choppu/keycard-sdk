import { CryptoUtils } from "./crypto-utils";

export namespace GlobalPlatformCrypto {
  export function appendDESPadding(data: Uint8Array) : Uint8Array {
    let paddingLength = 8 - (data.length % 8);
    let paddedData = new Uint8Array(data.length + paddingLength);
    paddedData.set(data, 0);
    paddedData[data.length] = 0x80;
    return paddedData;
  }

  export function mac3des(key: Uint8Array, data: Uint8Array, iv: Uint8Array) : Uint8Array {
    return;
  }

  export function verifyCryptogram(key: Uint8Array, hostChallenge: Uint8Array, cardChallenge: Uint8Array, cardCryptogram: Uint8Array) : boolean {
    let data = new Uint8Array(hostChallenge.length + cardChallenge.length);
    data.set(hostChallenge, 0);
    data.set(cardChallenge, hostChallenge.length);

    let calculated = mac3des(key, appendDESPadding(data), new Uint8Array(8));

    return CryptoUtils.Uint8ArrayEqual(calculated , cardCryptogram);
  }

  export function deriveSCP02SessionKey(scp02Key: Uint8Array, seq: Uint8Array, derivationPurpose: Uint8Array) : Uint8Array {
    return;
  }

  
}