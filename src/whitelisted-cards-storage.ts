export interface WhitelistedPubKeysStorage {
  addPubKeyToWhitelisted(cardPubKey: Uint8Array): Promise<void>;
  getWhitelistedPubKeys(): Promise<Uint8Array[]>;
  deleteWhitelistedPubKey(cardPubKey: Uint8Array): Promise<void>;
}