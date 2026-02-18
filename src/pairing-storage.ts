export interface PairingStorage {
  putPairing(instanceUID: Uint8Array, pairing: string): Promise<void>;
  getPairing(instanceUID: Uint8Array): Promise<string | null>;
  deletePairing(instanceUID: Uint8Array): Promise<void>;
}