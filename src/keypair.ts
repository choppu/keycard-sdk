export class KeyPair {
  privateKey: Uint8Array;
  publicKey: Uint8Array;

  constructor(privatekey: Uint8Array, publicKey: Uint8Array) {
    this.privateKey = privatekey;
    this.publicKey = publicKey;
  }
}