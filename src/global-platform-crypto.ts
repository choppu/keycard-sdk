import { CryptoUtils } from "./crypto-utils";

const CryptoJS = require('crypto-js');

export namespace GlobalPlatformCrypto {
  function resizeKey8(key: Uint8Array) : Uint8Array {
    return key.subarray(0, 8);
  }

  function resizeKey24(key: Uint8Array) : Uint8Array {
    let newKey = new Uint8Array(24);
    newKey.set(key.subarray(0, 16), 0);
    newKey.set(key.subarray(0, 8), 16);
    return newKey;
  }

  export function ecb3des(encKey: Uint8Array, data: Uint8Array) : Uint8Array {
    let dataWArray = CryptoJS.lib.WordArray.create(data);
    let sessionEncKeyWArray = CryptoJS.lib.WordArray.create(resizeKey24(encKey));
    let encData = CryptoJS.TripleDES.encrypt(dataWArray, sessionEncKeyWArray, {mode: CryptoJS.mode.ECB, padding: CryptoJS.pad.NoPadding});

    return CryptoUtils.wordArrayToByteArray(encData.ciphertext);
  }

  export function kcv3des(key: Uint8Array) : Uint8Array {
    let encData = ecb3des(key, new Uint8Array(8));
    return encData.subarray(0, 3);
  }

  export function mac3des(encKey: Uint8Array, data: Uint8Array, iv: Uint8Array) : Uint8Array {
    let dataWArray = CryptoJS.lib.WordArray.create(data);
    let sessionEncKeyWArray = CryptoJS.lib.WordArray.create(resizeKey24(encKey));
    let ivWArray = CryptoJS.lib.WordArray.create(iv);
    let encDataWArray = CryptoJS.TripleDES.encrypt(dataWArray, sessionEncKeyWArray, {iv: ivWArray, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.NoPadding});
    let encData = CryptoUtils.wordArrayToByteArray(encDataWArray.ciphertext);
    return encData.subarray(16, 24);
  }

  export function macFull3des(encKey: Uint8Array, data: Uint8Array, iv: Uint8Array) : Uint8Array {
    let encKeyDESWArray = CryptoJS.lib.WordArray.create(resizeKey8(encKey));
    let encKey3DESWArray = CryptoJS.lib.WordArray.create(resizeKey24(encKey));
    let shortDataWArray = CryptoJS.lib.WordArray.create(data.subarray(0, data.byteLength - 8));
    let iv3DES = iv;

    if (data.byteLength > 8) {
      let ivWArray = CryptoJS.lib.WordArray.create(iv);
      let tmpWArr = CryptoJS.DES.encrypt(shortDataWArray, encKeyDESWArray, {iv: ivWArray, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.NoPadding});
      let tmp = CryptoUtils.wordArrayToByteArray(tmpWArr.ciphertext);
      iv3DES.set(tmp.subarray(tmp.byteLength - 8), 0);
    }

    let dataWArray = CryptoJS.lib.WordArray.create(data.subarray(data.byteLength - 8));
    let iv3DESWArray = CryptoJS.lib.WordArray.create(iv3DES);
    let encDataWArr = CryptoJS.TripleDES.encrypt(dataWArray, encKey3DESWArray, {iv: iv3DESWArray, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.NoPadding});
    let encData = CryptoUtils.wordArrayToByteArray(encDataWArr.ciphertext);

    return encData.subarray(encData.byteLength - 8);
  }

  export function encryptICV(macEncKey: Uint8Array, mac: Uint8Array) : Uint8Array {
    let dataWArray = CryptoJS.lib.WordArray.create(mac);
    let sessionEncKeyWArray = CryptoJS.lib.WordArray.create(resizeKey8(macEncKey));
    let encData = CryptoJS.DES.encrypt(dataWArray, sessionEncKeyWArray, {mode: CryptoJS.mode.ECB, padding: CryptoJS.pad.NoPadding});

    return CryptoUtils.wordArrayToByteArray(encData.ciphertext);
  }

  export function appendDESPadding(data: Uint8Array) : Uint8Array {
    let paddingLength = 8 - (data.byteLength % 8);
    let paddedData = new Uint8Array(data.byteLength + paddingLength);
    paddedData.set(data, 0);
    paddedData[data.byteLength] = 0x80;
    return paddedData;
  }

  export function deriveSCP02SessionKey(encKey: Uint8Array, seq: Uint8Array, derivationPurpose: Uint8Array) : Uint8Array {
    let derivationData = new Uint8Array(16);
    derivationData.set(derivationPurpose.subarray(0, 2), 0);
    derivationData.set(seq.subarray(0, 2), 2);

    let dataWArray = CryptoJS.lib.WordArray.create(derivationData);
    let sessionEncKeyWArray = CryptoJS.lib.WordArray.create(resizeKey24(encKey));
    let iv = CryptoJS.lib.WordArray.create(new Uint8Array(8));
    let encData = CryptoJS.TripleDES.encrypt(dataWArray, sessionEncKeyWArray, {iv: iv, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.NoPadding});

    return CryptoUtils.wordArrayToByteArray(encData.ciphertext);
  }
}