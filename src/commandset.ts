import { CardChannel } from "./card-channel"
import { SecureChannel } from "./secure-channel"
import { ApplicationInfo } from "./application-info"
import { Pairing } from "./pairing"
import { APDUResponse } from "./apdu-response"
import { APDUCommand } from "./apdu-command"
import { CryptoUtils } from "./crypto-utils"
import { BIP32KeyPair } from "./bip32key"
import { KeyPath } from "./key-path"
import { Constants } from "./constants"

const CryptoJS = require("crypto-js");

const INS_INIT = 0xfe;
const INS_GET_STATUS = 0xf2;
const INS_SET_NDEF = 0xf3;
const INS_IDENTIFY_CARD = 0x14;
const INS_VERIFY_PIN = 0x20;
const INS_CHANGE_PIN = 0x21;
const INS_UNBLOCK_PIN = 0x22;
const INS_LOAD_KEY = 0xd0;
const INS_DERIVE_KEY = 0xd1;
const INS_GENERATE_MNEMONIC = 0xd2;
const INS_REMOVE_KEY = 0xd3;
const INS_GENERATE_KEY = 0xd4;
const INS_SET_PINLESS_PATH = 0xc1;
const INS_EXPORT_KEY = 0xc2;
const INS_GET_DATA = 0xca;

const CHANGE_PIN_P1_USER_PIN = 0x00;
const CHANGE_PIN_P1_PUK = 0x01;
const CHANGE_PIN_P1_PAIRING_SECRET = 0x02;

const LOAD_KEY_P1_EC = 0x01;
const LOAD_KEY_P1_EXT_EC = 0x02;
const LOAD_KEY_P1_SEED = 0x03;

const SIGN_P1_CURRENT_KEY = 0x00;
const SIGN_P1_DERIVE = 0x01;
const SIGN_P1_DERIVE_AND_MAKE_CURRENT = 0x02;
const SIGN_P1_PINLESS = 0x03;

const STORE_DATA_P1_NDEF = 0x01;

const EXPORT_KEY_P1_CURRENT = 0x00;
const EXPORT_KEY_P1_DERIVE = 0x01;
const EXPORT_KEY_P1_DERIVE_AND_MAKE_CURRENT = 0x02;

const EXPORT_KEY_P2_PRIVATE_AND_PUBLIC = 0x00;
const EXPORT_KEY_P2_PUBLIC_ONLY = 0x01;

const KEYCARD_AID = new Uint8Array([0xa0, 0x00, 0x00, 0x08, 0x04, 0x00, 0x01, 0x01, 0x01]);


export class Commandset {
  apduChannel: CardChannel;
  secureChannel: SecureChannel;
  applicationInfo: ApplicationInfo;

  constructor(channel: CardChannel) {
    this.apduChannel = channel;
    this.secureChannel = new SecureChannel();
    this.applicationInfo = null;
  }

  setSecureChannel(secureChannel: SecureChannel) : void {
    this.secureChannel = secureChannel;
  }

  getPairing() : Pairing {
    return this.secureChannel.pairing;
  }

  setPairing(pairing: Pairing) : void {
    this.secureChannel.setPairing(pairing);
  }

  async select() : Promise<APDUResponse> {
    let selectApplet = new APDUCommand(0x00, 0xa4, 4, 0, KEYCARD_AID);
    let resp = await this.apduChannel.send(selectApplet);

    if (resp.sw == 0x9000) {
      this.applicationInfo = new ApplicationInfo(resp.data);

      if (this.applicationInfo.hasSecureChannelCapability()) {
        this.secureChannel.generateSecret(this.applicationInfo.secureChannelPubKey);
        this.secureChannel.reset();
      }
    }

    return resp;
  }

  async autoOpenSecureChannel() : Promise<void> {
    return this.secureChannel.autoOpenSecureChannel(this.apduChannel);
  }

  pairingPasswordToSecret(pairingPassword: string) : Uint8Array {
    let salt = "Keycard Pairing Password Salt";
    let iterationCount = 50000;
    let kSize = 256 / 32;
    let PBKDF2WordArr = CryptoJS.PBKDF2(pairingPassword, salt, {keySize: kSize, iterations: iterationCount, hasher: CryptoJS.algo.SHA256});
    let PBKDF2Bytes = CryptoUtils.wordArrayToByteArray(PBKDF2WordArr);

    return PBKDF2Bytes;
  }

  async autoPair(pairingData: string | Uint8Array) : Promise<void> {
    if (typeof pairingData === "string") {
      pairingData = this.pairingPasswordToSecret(pairingData);
    }

    return this.secureChannel.autoPair(this.apduChannel, pairingData);
  }

  async autoUnpair() : Promise<void> {
    return this.secureChannel.autoUnpair(this.apduChannel);
  }

  async openSecureChannel(index: number, data: Uint8Array) : Promise<APDUResponse> {
    return this.secureChannel.openSecureChannel(this.apduChannel, index, data);
  }

  async mutuallyAuthenticate(data?: Uint8Array) : Promise<APDUResponse> {
    return this.secureChannel.mutuallyAuthenticate(this.apduChannel, data);
  }

  async pair(p1: number, data: Uint8Array) : Promise<APDUResponse> {
    return this.secureChannel.pair(this.apduChannel, p1, data);
  }

  async unpair(p1: number) : Promise<APDUResponse> {
    return this.secureChannel.unpair(this.apduChannel, p1);
  }

  async unpairOthers() : Promise<void> {
    return this.secureChannel.unpairOthers(this.apduChannel);
  }

  async identifyCard(challenge: Uint8Array) : Promise<APDUResponse> {
    let identifyCard = this.secureChannel.protectedCommand(0x80, INS_IDENTIFY_CARD, 0, 0, challenge);
    return this.secureChannel.transmit(this.apduChannel, identifyCard);
  }

  async getStatus(info: number) : Promise<APDUResponse> {
    let getStatus = this.secureChannel.protectedCommand(0x80, INS_GET_STATUS, info, 0, new Uint8Array(0));
    return this.secureChannel.transmit(this.apduChannel, getStatus);
  }

  async verifyPIN(pin: string) : Promise<APDUResponse> {
    let verifyPIN = this.secureChannel.protectedCommand(0x80, INS_VERIFY_PIN, 0, 0, CryptoUtils.stringToUint8Array(pin));
    return this.secureChannel.transmit(this.apduChannel, verifyPIN);
  }

  async changePIN(pin: string | Uint8Array, pinType = CHANGE_PIN_P1_USER_PIN) : Promise<APDUResponse> {
    pin = (typeof pin === "string") ? CryptoUtils.stringToUint8Array(pin) : pin;
    let changePIN = this.secureChannel.protectedCommand(0x80, INS_CHANGE_PIN, pinType, 0, pin);
    return this.secureChannel.transmit(this.apduChannel, changePIN);
  }

  async changePUK(puk: string) : Promise<APDUResponse> {
    return this.changePIN(CryptoUtils.stringToUint8Array(puk), CHANGE_PIN_P1_PUK);
  }

  async changePairingPassword(pairingPassword: string) : Promise<APDUResponse> {
    return this.changePIN(this.pairingPasswordToSecret(pairingPassword), CHANGE_PIN_P1_PAIRING_SECRET);
  }

  async unblockPIN(puk: string, newPin: string) : Promise<APDUResponse> {
    let unblockPIN = this.secureChannel.protectedCommand(0x80, INS_UNBLOCK_PIN, 0, 0, CryptoUtils.stringToUint8Array(puk + newPin));
    return this.secureChannel.transmit(this.apduChannel, unblockPIN);
  }

  async loadKey(data: Uint8Array, keyType: number) : Promise<APDUResponse> {
    let loadKey = this.secureChannel.protectedCommand(0x80, INS_LOAD_KEY, keyType, 0, data);
    return this.secureChannel.transmit(this.apduChannel, loadKey);
  }

  async loadSeed(seed: Uint8Array) : Promise<APDUResponse> {
    return this.loadKey(seed, LOAD_KEY_P1_SEED);
  }

  loadBIP32KeyPair(keyPair: BIP32KeyPair, omitPublic = false) {
    let p1;

    if (keyPair.isExtended()) {
      p1 = LOAD_KEY_P1_EXT_EC;
    } else {
      p1 = LOAD_KEY_P1_EC;
    }

    return this.loadKey(keyPair.toTLV(!omitPublic), p1);
  }

  loadKeyPair(publicKey: Uint8Array, privateKey: Uint8Array, chainCode: Uint8Array) {
    return this.loadBIP32KeyPair(new BIP32KeyPair(privateKey, chainCode, publicKey), publicKey == null);
  }

  async generateMnemonic(checksum: number) : Promise<APDUResponse> {
    let generateMnemonic = this.secureChannel.protectedCommand(0x80, INS_GENERATE_MNEMONIC, checksum, 0, new Uint8Array(0));
    return this.secureChannel.transmit(this.apduChannel, generateMnemonic);
  }

  async removeKey() : Promise<APDUResponse> {
    let removeKey = this.secureChannel.protectedCommand(0x80, INS_REMOVE_KEY, 0, 0, new Uint8Array(0));
    return this.secureChannel.transmit(this.apduChannel, removeKey);
  }

  async generateKey() : Promise<APDUResponse> {
    let generateKey = this.secureChannel.protectedCommand(0x80, INS_GENERATE_KEY, 0, 0, new Uint8Array(0));
    return this.secureChannel.transmit(this.apduChannel, generateKey);
  }

  async sign(data: Uint8Array, p1 = SIGN_P1_CURRENT_KEY) : Promise<APDUResponse> {
    let sign = this.secureChannel.protectedCommand(0x80, Constants.INS_SIGN, p1, 0x00, data);
    return this.secureChannel.transmit(this.apduChannel, sign);
  }

  async signWithPath(hash: Uint8Array, path: string, makeCurrent: boolean) : Promise<APDUResponse> {
    let keyPath = new KeyPath(path);
    let pathData = keyPath.data;
    let data = new Uint8Array(hash.byteLength + pathData.byteLength);
    data.set(hash, 0);
    data.set(pathData, hash.length);
    return this.sign(data, keyPath.source | (makeCurrent ? SIGN_P1_DERIVE_AND_MAKE_CURRENT : SIGN_P1_DERIVE));
  }

  async signPinless(hash: Uint8Array) : Promise<APDUResponse> {
    return this.sign(hash, SIGN_P1_PINLESS);
  }

  async deriveKey(data: string | Uint8Array, source?: number) : Promise<APDUResponse> {
    if (typeof data === "string") {
      let path = new KeyPath(data);
      data = path.data;
      source = path.source;
    }

    source = (source == undefined) ? Constants.DERIVE_SOURCE.deriveP1SourceMaster : source;

    let deriveKey = this.secureChannel.protectedCommand(0x80, INS_DERIVE_KEY, source, 0x00, data);
    return this.secureChannel.transmit(this.apduChannel, deriveKey);
  }

  async setPinlessPath(data: string | Uint8Array) : Promise<APDUResponse> {
    if (typeof data === "string") {
      let keyPath = new KeyPath(data);

      if (keyPath.source != Constants.DERIVE_SOURCE.deriveP1SourceMaster) {
        throw new Error("Error: Only absolute paths can be set as PINLESS path");
      } else {
        data = keyPath.data;
      }
    }

    let setPinlessPath = this.secureChannel.protectedCommand(0x80, INS_SET_PINLESS_PATH, 0x00, 0x00, data);
    return this.secureChannel.transmit(this.apduChannel, setPinlessPath);
  }

  async resetPinlessPath() : Promise<APDUResponse> {
    return this.setPinlessPath(new Uint8Array(0));
  }

  async exportKey(derivationOptions: number, publicOnly: boolean, keypath: string | Uint8Array, makeCurrent?: boolean, source?: number) : Promise<APDUResponse> {
    if(typeof keypath === "string") {
      let path = new KeyPath(keypath);
      keypath = path.data;
      source = path.source;
    }

    if ((makeCurrent != undefined) && (source != undefined)) {
      derivationOptions = source | (makeCurrent ? EXPORT_KEY_P1_DERIVE_AND_MAKE_CURRENT : EXPORT_KEY_P1_DERIVE);
    }

    let p2 = publicOnly ? EXPORT_KEY_P2_PUBLIC_ONLY : EXPORT_KEY_P2_PRIVATE_AND_PUBLIC;
    let exportKey = this.secureChannel.protectedCommand(0x80, INS_EXPORT_KEY, derivationOptions, p2, keypath);
    return this.secureChannel.transmit(this.apduChannel, exportKey);
  }

  async exportCurrentKey(publicOnly: boolean) : Promise<APDUResponse> {
    return this.exportKey(EXPORT_KEY_P1_CURRENT, publicOnly, new Uint8Array(0));
  }

  async getData(dataType: number) : Promise<APDUResponse> {
    let getData = this.secureChannel.protectedCommand(0x80, INS_GET_DATA, dataType, 0, new Uint8Array(0));
    return this.secureChannel.transmit(this.apduChannel, getData);
  }

  async storeData(data: Uint8Array, dataType: number) : Promise<APDUResponse> {
    let storeData = this.secureChannel.protectedCommand(0x80, Constants.INS_STORE_DATA, dataType, 0, data);
    return this.secureChannel.transmit(this.apduChannel, storeData);
  }

  async setNDEF(ndef: Uint8Array) : Promise<APDUResponse> {
    if ((this.applicationInfo.appVersion >> 8) > 2) {
      if ((ndef.byteLength - 2) != ((ndef[0] << 8) | ndef[1])) {
        let tmp = new Uint8Array(ndef.byteLength + 2);
        tmp[0] = ndef.byteLength >> 8;
        tmp[1] = ndef.byteLength & 0xff;
        tmp.set(ndef, 2);
        ndef = tmp;
      }

      return this.storeData(ndef, STORE_DATA_P1_NDEF);
    } else {
      let setNDEF = this.secureChannel.protectedCommand(0x80, INS_SET_NDEF, 0, 0, ndef);
      return this.secureChannel.transmit(this.apduChannel, setNDEF);
    }
  }

  async init(pin: string, puk: string, sharedSecret: string | Uint8Array) : Promise<APDUResponse> {
    if (typeof sharedSecret === "string") {
      sharedSecret = this.pairingPasswordToSecret(sharedSecret);
    }

    let pinByteArr = CryptoUtils.stringToUint8Array(pin);
    let pukByteArr = CryptoUtils.stringToUint8Array(puk);
    let initData = new Uint8Array(pinByteArr.byteLength + pukByteArr.byteLength + sharedSecret.byteLength);

    initData.set(pinByteArr, 0);
    initData.set(pukByteArr, pinByteArr.byteLength);
    initData.set(sharedSecret, pinByteArr.byteLength + pukByteArr.byteLength);

    let init = new APDUCommand(0x80, INS_INIT, 0, 0, this.secureChannel.oneShotEncrypt(initData));
    return this.apduChannel.send(init);
  }

}