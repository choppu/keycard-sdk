import { Certificate } from "../src/certificate";
import { BIP32KeyPair } from "../src/bip32key"

const secp256k1 = require('secp256k1');

const privKey = new Uint8Array([186, 240, 247, 237, 145,  53, 118,  68, 96, 251,  38, 229,  65, 202, 162, 134, 6, 118, 195,  23,  79,  43,  94,  54, 100, 177, 162, 242,  73, 105,  48,  83]);
const publicKey = secp256k1.publicKeyCreate(privKey)
const caKeyPair = new BIP32KeyPair(privKey, new Uint8Array(0), publicKey);
const identKeyPair = Certificate.generateIdentKeyPair();
const certificate = Certificate.generateNewCertificate(caKeyPair);

test('Certificate constructor function', () => {
  expect(certificate instanceof Certificate).toBe(true);
});