import { SCP02Keys } from "./scp02-keys";

export class SCP02Session {
  scp02Keys: SCP02Keys;
  cardChallenge: Uint8Array;
  fallbackKeys: boolean;

  constructor(scp02Keys: SCP02Keys, cardChallenge: Uint8Array) {
    this.scp02Keys = scp02Keys;
    this.cardChallenge = cardChallenge;
    this.fallbackKeys = false;
  }

  useFallbackKeys() : void {
    this.fallbackKeys = true;
  }
}