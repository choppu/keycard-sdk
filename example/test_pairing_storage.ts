import { PairingStorage } from "../src";

export class TestStorage implements PairingStorage {
  storage: { [key: string]: string } = {};

  public static hx(arr: Uint8Array) : string {
    return Buffer.from(arr).toString('hex');
  }

  async putPairing(instanceUID: Uint8Array, pairing: string): Promise<void> {
    return new Promise((resolve,reject) => {
      try {
        let uid = TestStorage.hx(instanceUID);
        this.storage[uid] = pairing;
        resolve();
      } catch(err: any) {
        reject(err);
      } 
    });
  }

  async getPairing(instanceUID: Uint8Array): Promise<string | null> {
    return new Promise((resolve,reject) => {
      try {
        let uid = TestStorage.hx(instanceUID);
        resolve(this.storage[uid]);
      } catch(err: any) {
        reject(err);
      } 
    });
  }

  async deletePairing(instanceUID: Uint8Array): Promise<void> {
    return new Promise((resolve,reject) => {
      try {
        let uid = TestStorage.hx(instanceUID);
        delete this.storage[uid];
        resolve();
      } catch(err: any) {
        reject(err);
      } 
    });
  }
}
