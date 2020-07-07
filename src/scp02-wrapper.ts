export class SCP02Wrapper {
  macKey: Uint8Array;
  icv: Uint8Array;

  constructor(macKey: Uint8Array) {
    this.macKey = macKey;
    this.icv = new Uint8Array(8);
  }
}