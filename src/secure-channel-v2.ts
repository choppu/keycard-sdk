import { randomBytes } from "@noble/hashes/utils";
import * as secp from '@noble/secp256k1';
import { APDUCommand } from "./apdu-command.ts";
import { APDUException } from "./apdu-exception.ts";
import { APDUResponse } from "./apdu-response.ts";
import { CardChannel } from "./card-channel.ts";
import { Certificate } from "./certificate.ts";
import { CryptoUtils } from "./crypto-utils.ts";
import { Pairing } from "./pairing.ts";
import { SecureChannel } from "./secure-channel.ts";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha2";
import { AESCCM } from "./aes-ccm.ts";

const PROTOCOL_LABEL_ARR = ['s', 'c', '_', 'v', '2', '_', 'c', 'c', 'm' ];
const PROTOCOL_LABEL = new Uint8Array(PROTOCOL_LABEL_ARR.map(c => c.charCodeAt(0)));
const HKDF_SALT_SIZE = 32;
const PUBKEY_SIZE = 65;       // uncompressed secp256k1 point
const OKM_SIZE = 32;
const AES_KEY_SIZE = 16;
const CCM_NONCE_SIZE = 13;

const INS_OPEN_SECURE_CHANNEL = 0x10;
const INS_SECURED_APDU = 0x18;

export class SecureChannelV2 implements SecureChannel {
  cardIdentPub!: Uint8Array | null;
  cardPublicKeys: Uint8Array[];
  whitelistedCardPublicKeys: Uint8Array[];
  nonceCounter: Uint8Array;
  open: boolean;
  private clientEphPub!: Uint8Array | null;
  private keyH2C!: Uint8Array | null;
  private keyC2H!: Uint8Array | null;

  constructor(caPublicKeys: Uint8Array[], whitelistedCardPublicKeys: Uint8Array[]) {
    this.cardPublicKeys = caPublicKeys;
    this.whitelistedCardPublicKeys = whitelistedCardPublicKeys;
    this.nonceCounter = new Uint8Array(CCM_NONCE_SIZE);
    this.open = false;
  }

  async autoOpenSecureChannel(apduChannel: CardChannel): Promise<void> {
    try {
      const salt = randomBytes(HKDF_SALT_SIZE);

      // Generate client ephemeral key pair
      const { secretKey } = secp.keygen();
      this.clientEphPub = secp.getPublicKey(secretKey, false)  ;

      // Build request: hkdf_salt || client_eph_pub (uncompressed)
      const requestData = new Uint8Array(HKDF_SALT_SIZE + PUBKEY_SIZE);
      requestData.set(salt, 0);
      requestData.set(this.clientEphPub, HKDF_SALT_SIZE);

      const response = (await this.openSecureChannel(apduChannel, 0, requestData));
      response.checkOK('OPEN SECURE CHANNEL failed');
      this.processHandshakeResponse(salt, secretKey, response.data);
    } catch(err: any) {
      throw (err);
    }
  }

  processHandshakeResponse(salt: Uint8Array, clientEphPriv: Uint8Array, cardResponse: Uint8Array) : void {
    // Parse card response: card_eph_pub (65B) || sig (DER, variable)
    if (cardResponse.length < PUBKEY_SIZE + 2) {
      throw new APDUException("Invalid handshake response: too short");
    }

    const cardEphPub = cardResponse.subarray(0, PUBKEY_SIZE);
    const signature = cardResponse.subarray(PUBKEY_SIZE);

    // ECDH key agreement
    const sharedSecret = secp.getSharedSecret(clientEphPriv, cardEphPub);

    // HKDF-SHA256 key derivation
    const okm = hkdf(sha256, sharedSecret, salt, PROTOCOL_LABEL, OKM_SIZE);

    // Set session keys: key_h2c = OKM[0..15], key_c2h = OKM[16..31]
    this.keyH2C = okm.subarray(0, AES_KEY_SIZE);
    this.keyC2H = okm.subarray(AES_KEY_SIZE);

    // Verify card's ECDSA signature over transcript
    // transcript = hkdf_salt || client_eph_pub || card_eph_pub
    this.verifyCardSignature(salt, this.clientEphPub!, cardEphPub, signature);

    // Initialize nonce counter to zero
    this.nonceCounter = new Uint8Array(CCM_NONCE_SIZE);
    this.open = true;
  }

  async autoPair(apduChannel: CardChannel, pairingMode: number, sharedSecret: Uint8Array): Promise<void> {
    throw new Error("Pairing is not supported in Secure Channel V2");
  }

  async autoUnpair(apduChannel: CardChannel): Promise<void> {
    throw new Error("Unpairing is not supported in Secure Channel V2");
  }

  async unpairOthers(apduChannel: CardChannel): Promise<void> {
    throw new Error("Unpairing is not supported in Secure Channel V2");
  }

  async openSecureChannel(apduChannel: CardChannel, index: number, data: Uint8Array): Promise<APDUResponse> {
    this.open = false;
    const cmd = new APDUCommand(0x80, INS_OPEN_SECURE_CHANNEL, 0, 0, data);
    return await apduChannel.send(cmd);
  }

  async mutuallyAuthenticate(apduChannel: CardChannel, data?: Uint8Array): Promise<APDUResponse> {
    throw new Error("Mutual authentication is not a separate step in Secure Channel V2");
  }
  pair(apduChannel: CardChannel, p1: number, p2: number, data: Uint8Array): Promise<APDUResponse> {
    throw new Error("Method not implemented.");
  }
  unpair(apduChannel: CardChannel, p1: number): Promise<APDUResponse> {
    throw new Error("Method not implemented.");
  }
  protectedCommand(cla: number, ins: number, p1: number, p2: number, data: Uint8Array): APDUCommand {
    if (!this.open) {
      return new APDUCommand(cla, ins, p1, p2, data);
    }

    // Build inner APDU: CLA | INS | P1 | P2 | LC | data
    const innerAPDU = new Uint8Array(data.length + 5);
    innerAPDU[0] = cla & 0xFF;
    innerAPDU[1] = ins & 0xFF;
    innerAPDU[2] = p1 & 0xFF;
    innerAPDU[3] = p2 & 0xFF;
    innerAPDU[4] = data.length & 0xFF;
    innerAPDU.set(data, 5);

    const aesCCM = new AESCCM(this.keyH2C!);
    const ciphertext = aesCCM.encrypt(innerAPDU, this.nonceCounter);

    return new APDUCommand(0x80, INS_SECURED_APDU, 0, 0, ciphertext);
  }
  
  async transmit(apduChannel: CardChannel, apdu: APDUCommand): Promise<APDUResponse> {
    const resp = await apduChannel.send(apdu);

    if (resp.sw != 0x9000) {
      this.open = false;
    }

    if(this.open) {
      const aesCCM = new AESCCM(this.keyC2H!);
      const ciphertext = resp.data;
      const plaintext = aesCCM.decrypt(ciphertext, this.nonceCounter);
      this.incrementNonce();
      return new APDUResponse(plaintext);
    } else {
      return resp;
    }
  }

  getPairing(): Pairing | null {
    return null;
  }

  setPairing(pairing: Pairing): void {
    throw new Error("Method not implemented.");
  }

  setCardCertificate(certData: Uint8Array) : void {
    const cert = Certificate.fromTLV(certData);
    this.cardIdentPub = cert.identPub;

    // Check if the card's identity public key is whitelisted
    const whitelisted = this.isCardWhitelisted(this.cardIdentPub);

    // Check if the CA public key is trusted
    const caPub = cert.publicKey; // recovered CA public key (compressed)
    const caTrusted = this.isCardTrusted(caPub!);

    if (!caTrusted && !whitelisted) {
      throw new APDUException("Card certificate verification failed: unknown CA public key and card not whitelisted");
    }
  }

  reset(): void {
    this.open = false;
    this.keyH2C = null;
    this.keyC2H = null;
    this.nonceCounter = new Uint8Array(CCM_NONCE_SIZE);
    this.cardIdentPub = null;
    this.clientEphPub = null;
  }

  isCardWhitelisted(identPub: Uint8Array) : boolean {
    for (let i = 0; i <  this.whitelistedCardPublicKeys.length; i++) {
      if (CryptoUtils.Uint8ArrayEqual(this.whitelistedCardPublicKeys[i], identPub)) {
        return true;
      }
    }

    return false;
  }

  isCardTrusted(caPub: Uint8Array) : boolean {
    for (let i = 0; i <  this.cardPublicKeys.length; i++) {
      if (CryptoUtils.Uint8ArrayEqual(this.cardPublicKeys[i], caPub)) {
        return true;
      }
    }

    return false;
  }

  private async verifyCardSignature(salt: Uint8Array, clientPub: Uint8Array, cardPub: Uint8Array, signature: Uint8Array) : Promise<void> {
    try {
      let hashBytes = sha256.create();
      hashBytes.update(PROTOCOL_LABEL);
      hashBytes.update(salt);
      hashBytes.update(clientPub);
      hashBytes.update(cardPub);
      let keyData = hashBytes.digest();

      if (this.cardIdentPub == null) {
        throw new APDUException("Card identity public key not available");
      }

      if (!(await secp.verifyAsync(signature, keyData, cardPub))) {
        throw new APDUException("Card authentication failed: invalid signature");
      }
    } catch (err: any ) {
      throw new Error(err);
    }
  }

  private incrementNonce() : void {
    for (let i = CCM_NONCE_SIZE - 1; i >= 0; i--) {
      this.nonceCounter[i]++;
      if (this.nonceCounter[i] != 0) {
        return;
      }
    }
    // Overflow — session must be reset
    this.open = false;
    throw new Error("Nonce counter overflow — secure channel session expired");
  }
}