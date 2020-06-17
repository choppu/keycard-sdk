import { Pairing } from "./pairing"
import { CardChannel } from "./card-channel"
import { APDUResponse } from "./apdu-response";
import { APDUCommand } from "./apdu-command";
import { CryptoUtils } from "./crypto-utils";
import { APDUException } from "./apdu-exception";

const secp256k1 = require('secp256k1');
const CryptoJS = require('crypto-js');

const SC_SECRET_LENGTH = 32;
const SC_BLOCK_SIZE = 16;

const INS_OPEN_SECURE_CHANNEL = 0x10;
const INS_MUTUALLY_AUTHENTICATE = 0x11;
const INS_PAIR = 0x12;
const INS_UNPAIR = 0x13;

const PAIR_P1_FIRST_STEP = 0x00;
const PAIR_P1_LAST_STEP = 0x01;
  
const PAYLOAD_MAX_SIZE = 223;

const PAIRING_MAX_CLIENT_COUNT = 5;

const metaLength = 16;

export class SecureChannel {
  secret: Uint8Array;
  publicKey: Uint8Array;
  iv: Uint8Array;
  sessionEncKey: Uint8Array;
  sessionMacKey: Uint8Array;
  pairing: Pairing;
  open: boolean;

  constructor() {
    this.open = false;
  }

  generateSecret(keyData: Uint8Array) : void {
    let privKey = CryptoUtils.generateECPrivateKey();
    this.publicKey = secp256k1.publicKeyCreate(privKey, false);
    this.secret = secp256k1.ecdh(keyData, privKey);
  }

  setPairing(pairing: Pairing) : void {
    this.pairing = pairing;
  }

  processOpenSecureChannelResponse(response: APDUResponse) : void {
    let data = new Uint8Array(SC_SECRET_LENGTH);

    let hashBytes = CryptoJS.algo.SHA512.create();
    hashBytes.update(CryptoJS.lib.WordArray.create(this.secret));
    hashBytes.update(CryptoJS.lib.WordArray.create(this.pairing.pairingKey))
    data.set(response.data.slice(0, SC_SECRET_LENGTH));
    hashBytes.update(CryptoJS.lib.WordArray.create(data));
    let keyData = CryptoUtils.wordArrayToByteArray(hashBytes.finalize());

    this.iv = data.subarray(SC_SECRET_LENGTH, data.byteLength);
    this.sessionEncKey = keyData.subarray(0, SC_SECRET_LENGTH);
    this.sessionMacKey = keyData.subarray(SC_SECRET_LENGTH);
    this.open = true;
  }

  encryptAPDU(data: Uint8Array) : Uint8Array {
    let dataWArray = CryptoJS.lib.WordArray.create(data);
    let encData = CryptoJS.AES.encrypt(dataWArray, this.sessionEncKey, {iv: this.iv, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Iso97971});
    return CryptoUtils.wordArrayToByteArray(encData);
  }

  decryptAPDU(data: Uint8Array) : Uint8Array {
    let dataWArray = CryptoJS.lib.WordArray.create(data);
    let decData = CryptoJS.AES.decrypt(dataWArray, this.sessionEncKey, {iv: this.iv, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Iso97971});
    return CryptoUtils.wordArrayToByteArray(decData);
  }

  updateIV(meta: Uint8Array, data: Uint8Array) : void {
    let key = CryptoJS.lib.WordArray.create(this.sessionMacKey);
    let cmac = CryptoJS.algo.CMAC.create(key);
    cmac.update(CryptoJS.lib.WordArray.create(meta));
    cmac.update(CryptoJS.lib.WordArray.create(data));

    this.iv = CryptoUtils.wordArrayToByteArray(cmac.finalize());
  }

  protectedCommand(cla: number, ins: number, p1: number, p2: number, data: Uint8Array) : APDUCommand {
    let finalData;

    if (this.open) {
      data = this.encryptAPDU(data);
      let meta = new Uint8Array(metaLength);
      meta.set([cla, ins, p1, p2, (data.byteLength + SC_BLOCK_SIZE)])
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
      meta[0] = data.byteLength;
      let mac = new Uint8Array(this.iv.byteLength);
      mac.set(data.slice(0, this.iv.length), 0);
      data = data.subarray(this.iv.byteLength, data.byteLength);

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
    if (response.data.length != SC_SECRET_LENGTH) {
      throw new Error("Error: Invalid authentication data from the card");
    }
  }

  async autoOpenSecureChannel(apduChannel: CardChannel) : Promise<void> {
   let response = await this.openSecureChannel(apduChannel, this.pairing.pairingIndex, this.publicKey);
    this.processOpenSecureChannelResponse(response);
    
    response = await this.mutuallyAuthenticate(apduChannel);
    response.checkOK("MUTUALLY AUTHENTICATE failed");
    this.verifyMutuallyAuthenticateResponse(response);
  }

  async autoPair(apduChannel: CardChannel, sharedSecret: Uint8Array) : Promise<void> {
    let challenge = CryptoUtils.getRandomBytes(32);
    let resp = await this.pair(apduChannel, PAIR_P1_FIRST_STEP, challenge);
    resp.checkOK("Pairing failed on step 1");

    let respData = resp.data;
    let cardCryptogram = new Uint8Array(32);
    cardCryptogram.set(respData.slice(0, 32), 0);
    let cardChallenge = respData.subarray(32, respData.byteLength);
    let checkCryptogram;

    let sha256Data = CryptoJS.algo.SHA256.create();

    sha256Data.update(CryptoJS.lib.WordArray.create(sharedSecret));
    sha256Data.update(CryptoJS.lib.WordArray.create(challenge));
    checkCryptogram = CryptoUtils.wordArrayToByteArray(sha256Data.finalize());

    if (!CryptoUtils.Uint8ArrayEqual(checkCryptogram, cardCryptogram)) {
      throw new APDUException("Error: Invalid card cryptogram");
    }

    sha256Data.update(CryptoJS.lib.WordArray.create(sharedSecret));
    sha256Data.update(CryptoJS.lib.WordArray.create(cardChallenge));
    checkCryptogram = CryptoUtils.wordArrayToByteArray(sha256Data.finalize());

    resp = await this.pair(apduChannel, PAIR_P1_LAST_STEP, checkCryptogram);
    resp.checkOK("Pairing failed on step 2");
    respData = resp.data;

    sha256Data.update(CryptoJS.lib.WordArray.create(sharedSecret));
    sha256Data.update(CryptoJS.lib.WordArray.create(respData.subarray(1)));
    let pKey = CryptoUtils.wordArrayToByteArray(sha256Data.finalize());

    this.pairing = new Pairing(pKey, respData[0]);
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
    let encData = CryptoJS.AES.encrypt(initData, this.sessionEncKey, {iv: iv, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Iso97971});
    initData = CryptoUtils.wordArrayToByteArray(encData);
     
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