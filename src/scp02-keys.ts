export class SCP02Keys {
  encKey: Uint8Array;
  dekKey: Uint8Array;
  macKey: Uint8Array;

  constructor(encKey: Uint8Array, dekKey: Uint8Array, macKey: Uint8Array) {
    this.encKey = encKey;
    this.dekKey = dekKey;
    this.macKey = macKey;
  }
}