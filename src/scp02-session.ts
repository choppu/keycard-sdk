import { SCP02Keys } from "./scp02-keys.ts";

export class SCP02Session {
  scp02Keys: SCP02Keys;
  staticKeys: SCP02Keys;
  cardChallenge: Uint8Array;
  fallbackKeys: boolean;

  constructor(scp02Keys: SCP02Keys, cardChallenge: Uint8Array, staticKeys: SCP02Keys) {
    this.scp02Keys = scp02Keys;
    this.staticKeys = staticKeys;
    this.cardChallenge = cardChallenge;
    this.fallbackKeys = false;
  }

  useFallbackKeys() : void {
    this.fallbackKeys = true;
  }
}