export class SCP02Keys {
  encKey: Uint8Array;
  macKey: Uint8Array;
  dekKey: Uint8Array;

  constructor(encKey: Uint8Array, macKey: Uint8Array, dekKey: Uint8Array) {
    this.encKey = encKey;
    this.macKey = macKey;
    this.dekKey = dekKey;
  }
}