import { Pairing } from "./pairing.ts"
import { CardChannel } from "./card-channel.ts"
import { APDUResponse } from "./apdu-response.ts";
import { APDUCommand } from "./apdu-command.ts";
import { CryptoUtils } from "./crypto-utils.ts";
import { APDUException } from "./apdu-exception.ts";
import * as secp from '@noble/secp256k1';
import { sha256, sha512 } from "@noble/hashes/sha2";

const SC_SECRET_LENGTH = 32;
const SC_BLOCK_SIZE = 16;

const INS_OPEN_SECURE_CHANNEL = 0x10;
const INS_MUTUALLY_AUTHENTICATE = 0x11;
const INS_PAIR = 0x12;
const INS_UNPAIR = 0x13;

const PAIR_P1_FIRST_STEP = 0x00;
const PAIR_P1_LAST_STEP = 0x01;

const PAIRING_MAX_CLIENT_COUNT = 5;

const metaLength = 16;

export class SecureChannel {
  secret!: Uint8Array;
  publicKey!: Uint8Array;
  iv!: Uint8Array;
  sessionEncKey!: Uint8Array;
  sessionMacKey!: Uint8Array;
  pairing!: Pairing;
  open: boolean;

  constructor() {
    this.open = false;
  }

  generateSecret(keyData: Uint8Array) : void {
    let privKey = CryptoUtils.generateECPrivateKey();
    this.publicKey = secp.getPublicKey(privKey, false);
    this.secret = secp.getSharedSecret(privKey, keyData).subarray(1, 33);
  }

  setPairing(pairing: Pairing) : void {
    this.pairing = pairing;
  }

  processOpenSecureChannelResponse(response: APDUResponse) : void {
    let data = response.data;

    let hashBytes = sha512.create();
    hashBytes.update(this.secret);
    hashBytes.update(this.pairing.pairingKey)
    hashBytes.update(data.subarray(0, SC_SECRET_LENGTH));
    let keyData = hashBytes.digest();

    this.iv = data!.subarray(SC_SECRET_LENGTH, data!.byteLength);
    this.sessionEncKey = keyData.subarray(0, SC_SECRET_LENGTH);
    this.sessionMacKey = keyData.subarray(SC_SECRET_LENGTH);
    this.open = true;
  }

  encryptAPDU(data: Uint8Array) : Uint8Array {
    return CryptoUtils.aesEncrypt(data, this.sessionEncKey, this.iv, false);
  }

  decryptAPDU(data: Uint8Array) : Uint8Array {
    return CryptoUtils.aesDecrypt(data, this.sessionEncKey, this.iv);
  }

  updateIV(meta: Uint8Array, data: Uint8Array) : void {
    let mess = new Uint8Array(meta.byteLength + data.byteLength);
    mess.set(meta, 0);
    mess.set(data, meta.byteLength);
    let temp = CryptoUtils.aesEncrypt(mess, this.sessionMacKey, new Uint8Array(16), true);
    this.iv = temp.subarray(temp.byteLength - 16);
  }

  protectedCommand(cla: number, ins: number, p1: number, p2: number, data: Uint8Array) : APDUCommand {
    let finalData;

    if (this.open) {
      data = this.encryptAPDU(data);
      let meta = new Uint8Array(metaLength);
      meta.set([cla, ins, p1, p2, (data.byteLength + SC_BLOCK_SIZE)]);
      this.updateIV(meta, data);

      finalData = new Uint8Array(this.iv.byteLength + data.byteLength);
      finalData.set(this.iv, 0);
      finalData.set(data, this.iv.byteLength);
    } else {
      finalData = data;
    }

    return new APDUCommand(cla, ins, p1, p2, finalData);
  }

  async transmit(apduChannel: CardChannel, apdu: APDUCommand) : Promise<APDUResponse> {
    let resp = await apduChannel.send(apdu);

    if (resp.sw == 0x6982) {
      this.open = false;
    }

    if (this.open) {
      let data = resp.data;
      let meta = new Uint8Array(metaLength);
      meta[0] = data!.byteLength;
      let mac = data!.subarray(0, this.iv.byteLength);
      data = data!.subarray(this.iv.byteLength, data!.byteLength);

      let plainData = this.decryptAPDU(data);
      this.updateIV(meta, data);

      if (!CryptoUtils.Uint8ArrayEqual(this.iv, mac)) {
        throw new Error("Error: Invalid MAC");
      }

      return new APDUResponse(plainData);
    } else {
      return resp;
    }
  }

  async mutuallyAuthenticate(apduChannel: CardChannel, data?: Uint8Array) : Promise<APDUResponse> {
    data = (!data) ? new Uint8Array(CryptoUtils.getRandomBytes(SC_SECRET_LENGTH)) : data;
    let mutuallyAuthenticate = this.protectedCommand(0x80, INS_MUTUALLY_AUTHENTICATE, 0, 0, data);
    return this.transmit(apduChannel, mutuallyAuthenticate);
  }

  verifyMutuallyAuthenticateResponse(response: APDUResponse) : void {
    if (response.data!.length != SC_SECRET_LENGTH) {
      throw new Error("Error: Invalid authentication data from the card");
    }
  }

  async autoOpenSecureChannel(apduChannel: CardChannel) : Promise<void> {
    try {
      let response = (await this.openSecureChannel(apduChannel, this.pairing.pairingIndex, this.publicKey));
      response.checkOK(`Open Secure Channel cmd failed. Error code: ${response.sw}`);
      this.processOpenSecureChannelResponse(response);
    
      response = await this.mutuallyAuthenticate(apduChannel);
      response.checkOK("MUTUALLY AUTHENTICATE failed");
      this.verifyMutuallyAuthenticateResponse(response);
    } catch(err: any) {
      throw (err);
    }  
  }

  async autoPair(apduChannel: CardChannel, sharedSecret: Uint8Array) : Promise<void> {
    let challenge = CryptoUtils.getRandomBytes(32);
    let resp = await this.pair(apduChannel, PAIR_P1_FIRST_STEP, challenge);
    resp.checkOK("Pairing failed on step 1");

    let respData = resp.data;
    let cardCryptogram = new Uint8Array(32);
    cardCryptogram.set(respData!.slice(0, 32), 0);
    let cardChallenge = respData!.subarray(32, respData!.byteLength);
    let checkCryptogram;

    let sha256Data = sha256.create();

    sha256Data.update(sharedSecret);
    sha256Data.update(challenge);
    checkCryptogram = sha256Data.digest();

    if (!CryptoUtils.Uint8ArrayEqual(checkCryptogram, cardCryptogram)) {
      throw new APDUException(`Error: Invalid card cryptogram`);
    }

    sha256Data = sha256.create(); 
    sha256Data.update(sharedSecret);
    sha256Data.update(cardChallenge);
    checkCryptogram = sha256Data.digest();

    resp = await this.pair(apduChannel, PAIR_P1_LAST_STEP, checkCryptogram);
    resp.checkOK("Pairing failed on step 2");
    respData = resp.data;

    sha256Data = sha256.create();
    sha256Data.update(sharedSecret);
    sha256Data.update(respData!.subarray(1));
    let pKey = sha256Data.digest();

    this.pairing = new Pairing(pKey, respData![0]);
  }

  async autoUnpair(apduChannel: CardChannel) : Promise<void> {
    let resp = await this.unpair(apduChannel, this.pairing.pairingIndex);
    resp.checkOK("Unpairing failed");
  }

  async openSecureChannel(apduChannel: CardChannel, index: number, data: Uint8Array) : Promise<APDUResponse> {
    this.open = false;
    let openSecureChannel = new APDUCommand(0x80, INS_OPEN_SECURE_CHANNEL, index, 0, data);
    return await apduChannel.send(openSecureChannel);
  }

  async pair(apduChannel: CardChannel, p1: number, data: Uint8Array) : Promise<APDUResponse> {
    let pair = new APDUCommand(0x80, INS_PAIR, p1, 0, data);
    return this.transmit(apduChannel, pair);
  }

  async unpair(apduChannel: CardChannel, p1: number) : Promise<APDUResponse> {
    let unpair = this.protectedCommand(0x80, INS_UNPAIR, p1, 0, new Uint8Array(0));
    return this.transmit(apduChannel, unpair);
  }

  async unpairOthers(apduChannel: CardChannel) : Promise<void> {
    for (let i = 0; i < PAIRING_MAX_CLIENT_COUNT; i++) {
      if (i != this.pairing.pairingIndex) {
        let unpair = this.protectedCommand(0x80, INS_UNPAIR, i, 0, new Uint8Array(0));
        let resp = await this.transmit(apduChannel, unpair);
        resp.checkOK();
      }
    }
  }

  oneShotEncrypt(initData: Uint8Array) : Uint8Array {
    let iv = CryptoUtils.getRandomBytes(SC_BLOCK_SIZE);
    this.sessionEncKey = this.secret;
    initData = CryptoUtils.aesEncrypt(initData, this.sessionEncKey, iv, false);
     
    let encrypted = new Uint8Array(1 + this.publicKey.byteLength + iv.byteLength + initData.byteLength);
    encrypted[0] = this.publicKey.byteLength;
    encrypted.set(this.publicKey, 1);
    encrypted.set(iv, this.publicKey.byteLength + 1);
    encrypted.set(initData, (1 + this.publicKey.byteLength + iv.byteLength));
    
    return encrypted;
  }

  setOpen() : void {
    this.open = true;
  }

  reset() : void {
    this.open = false;
  }
}