import { Buffer } from "buffer";
import type { PairingStorage } from "../dist/pairing-storage.js";
import { WhitelistedPubKeysStorage } from "../dist/whitelisted-cards-storage.js";
import { CryptoUtils } from "../dist/crypto-utils.js";

export class TestWhitelistedPubKeysStorage implements WhitelistedPubKeysStorage {
  storage: Uint8Array[] = [];

  async addPubKeyToWhitelisted(pubKey: Uint8Array): Promise<void> {
    return new Promise((resolve,reject) => {
      try {
        this.storage.push(pubKey);
        resolve();
      } catch(err: any) {
        reject(err);
      }
    });
  }

  async getWhitelistedPubKeys(): Promise<Uint8Array []> {
    return new Promise((resolve,reject) => {
      try {
        resolve(this.storage);
      } catch(err: any) {
        reject(err);
      }
    });
  }

  async deleteWhitelistedPubKey(pubKey: Uint8Array): Promise<void> {
    return new Promise((resolve,reject) => {
      try {
        this.storage.splice(this.storage.findIndex((pK: Uint8Array) => CryptoUtils.Uint8ArrayEqual(pK, pubKey)), 1);
        resolve();
      } catch(err: any) {
        reject(err);
      }
    });
  }
}
