import { CardChannel } from "./card-channel";
import { SCP02Channel } from "./SCP02-channel";
import { SCP02Keys } from "./scp02-keys";
import { APDUResponse } from "./apdu-response";
import { APDUCommand } from "./apdu-command";
import { GlobalPlatformConstants } from "./global-platform-constants";
import { SCP02Session } from "./scp02-session";
import { APDUException } from "./apdu-exception";
import { GlobalPlatformCrypto } from "./global-platform-crypto";
import { CryptoUtils } from "./crypto-utils";
import { Constants } from "./constants";
import { Load } from "./load";

const gpDefaultKey = new Uint8Array([0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f]);
const gpDefaultKeys = new SCP02Keys(gpDefaultKey, gpDefaultKey, gpDefaultKey);
const developmentKey = new Uint8Array([0xc2, 0x12, 0xe0, 0x73, 0xff, 0x8b, 0x4b, 0xbf, 0xaf, 0xf4, 0xde, 0x8a, 0xb6, 0x55, 0x22, 0x1f]);

export class GlobalPlatformCommandset {
  apduChannel: CardChannel;
  secureChannel: SCP02Channel;
  scp02Keys: SCP02Keys;
  scp02Session: SCP02Session;

  constructor(apduChannel: CardChannel) {
    this.apduChannel = apduChannel;
    this.scp02Keys = new SCP02Keys(developmentKey, developmentKey, developmentKey);
  }

  async select(): Promise<APDUResponse> {
    let cmd = new APDUCommand(0x00, GlobalPlatformConstants.INS_SELECT, GlobalPlatformConstants.SELECT_P1_BY_NAME, 0, new Uint8Array(0));
    return this.apduChannel.send(cmd);
  }

  async initializeUpdate(hostChallenge: Uint8Array): Promise<APDUResponse> {
    let cmd = new APDUCommand(0x80, GlobalPlatformConstants.INS_INITIALIZE_UPDATE, 0, 0, hostChallenge, true);
    let apduResp = (await this.apduChannel.send(cmd)).checkOK();

    try {
      this.scp02Session = SCP02Channel.verifyChallenge(hostChallenge, this.scp02Keys, apduResp);
    } catch (err) {
      if (err instanceof APDUException) {
        this.scp02Session = SCP02Channel.verifyChallenge(hostChallenge, gpDefaultKeys, apduResp);
        this.scp02Session.useFallbackKeys();
      }
    }

    this.secureChannel = new SCP02Channel(this.apduChannel, this.scp02Session.scp02Keys);

    return apduResp;
  }

  async externalAuthenticate(hostChallenge: Uint8Array): Promise<APDUResponse> {
    let cardChallenge = this.scp02Session.cardChallenge;
    let data = new Uint8Array(cardChallenge.byteLength + hostChallenge.byteLength);
    data.set(cardChallenge, 0);
    data.set(hostChallenge, cardChallenge.byteLength);

    let paddedData = GlobalPlatformCrypto.appendDESPadding(data);
    let hostCryptogram = GlobalPlatformCrypto.mac3des(this.scp02Session.scp02Keys.encKey, paddedData, new Uint8Array(8));

    let cmd = new APDUCommand(0x84, GlobalPlatformConstants.INS_EXTERNAL_AUTHENTICATE, GlobalPlatformConstants.EXTERNAL_AUTHENTICATE_P1, 0, hostCryptogram);
    return this.secureChannel.send(cmd);
  }

  writeSCP02Key(arr: number[], key: Uint8Array): void {
    let encrypted = GlobalPlatformCrypto.ecb3des(this.scp02Session.scp02Keys.dekKey, key);
    let kcv = GlobalPlatformCrypto.kcv3des(key);

    arr.push(0x80);
    arr.push(encrypted.byteLength);
    arr.push.apply(arr, encrypted);
    arr.push(kcv.byteLength);
    arr.push.apply(arr, kcv);
  }

  putSCP02Keys(oldKvn: number, newKvn: number, encKey: Uint8Array, macKey = encKey, dekKey = encKey): Promise<APDUResponse> {
    if (encKey.byteLength != 16 || macKey.byteLength != 16 || dekKey.byteLength != 16) {
      throw new Error("Error: All keys must be 16-byte 3DES keys");
    }

    let keys = [newKvn];
    this.writeSCP02Key(keys, encKey);
    this.writeSCP02Key(keys, macKey);
    this.writeSCP02Key(keys, dekKey);

    let cmd = new APDUCommand(0x84, GlobalPlatformConstants.INS_PUT_KEY, oldKvn, 0x81, new Uint8Array(keys));
    return this.secureChannel.send(cmd);
  }

  async openSecureChannel(autoUpgradeKeys = true): Promise<void> {
    let hostChallenge = CryptoUtils.getRandomBytes(8);
    (await this.initializeUpdate(hostChallenge)).checkOK();
    (await this.externalAuthenticate(hostChallenge)).checkOK();

    if (this.scp02Session.fallbackKeys && autoUpgradeKeys) {
      (await this.putSCP02Keys(0, 1, this.scp02Keys.encKey, this.scp02Keys.macKey, this.scp02Keys.dekKey)).checkOK();
    }
  }

  async delete(aid: Uint8Array): Promise<APDUResponse> {
    let data = new Uint8Array(aid.byteLength + 2);
    data[0] = 0x4f;
    data[1] = aid.byteLength;
    data.set(aid, 2);

    let cmd = new APDUCommand(0x80, GlobalPlatformConstants.INS_DELETE, 0, 0, data);
    return this.secureChannel.send(cmd);
  }

  async deleteKeycardInstance(): Promise<APDUResponse> {
    return this.delete(GlobalPlatformConstants.getKeycardInstanceAID());
  }

  async deleteCashInstance(): Promise<APDUResponse> {
    return this.delete(GlobalPlatformConstants.CASH_INSTANCE_AID);
  }

  async deleteNDEFInstance(): Promise<APDUResponse> {
    return this.delete(GlobalPlatformConstants.NDEF_INSTANCE_AID);
  }

  async deleteKeycardPackage(): Promise<APDUResponse> {
    return this.delete(GlobalPlatformConstants.PACKAGE_AID);
  }

  async deleteKeycardInstancesAndPackage(): Promise<void> {
    (await this.deleteNDEFInstance()).checkSW(Constants.SW_OK, Constants.SW_REFERENCED_DATA_NOT_FOUND);
    (await this.deleteKeycardInstance()).checkSW(Constants.SW_OK, Constants.SW_REFERENCED_DATA_NOT_FOUND);
    (await this.deleteCashInstance()).checkSW(Constants.SW_OK, Constants.SW_REFERENCED_DATA_NOT_FOUND);
    (await this.deleteKeycardPackage()).checkSW(Constants.SW_OK, Constants.SW_REFERENCED_DATA_NOT_FOUND);
  }

  async installForLoad(aid: Uint8Array, sdAid = new Uint8Array(0)): Promise<APDUResponse> {
    let data = new Uint8Array(aid.byteLength + sdAid.byteLength + 5);
    data[0] = aid.byteLength;
    data.set(aid, 1);
    data[aid.length] = sdAid.byteLength;
    data.set(sdAid, aid.length + 1);

    let cmd = new APDUCommand(0x80, GlobalPlatformConstants.INS_INSTALL, GlobalPlatformConstants.INSTALL_FOR_LOAD_P1, 0, data);
    return this.secureChannel.send(cmd);
  }

  async load(data: Uint8Array, count: number, hasMoreBlocks: boolean): Promise<APDUResponse> {
    let p1 = hasMoreBlocks ? GlobalPlatformConstants.LOAD_P1_MORE_BLOCKS : GlobalPlatformConstants.LOAD_P1_LAST_BLOCK;
    let cmd = new APDUCommand(0x80, GlobalPlatformConstants.INS_LOAD, p1, count, data);
    return this.secureChannel.send(cmd);
  }

  async loadKeycardPackage(cap: Uint8Array, cb: (loadedBlock: number, blockCount: number) => void): Promise<void> {
    (await this.installForLoad(GlobalPlatformConstants.PACKAGE_AID)).checkOK();

    let load = new Load(cap);

    let block: Uint8Array;
    let steps = load.blocksCount();

    while ((block = load.nextDataBlock()) != null) {
      (await this.load(block, (load.count - 1), load.hasMore())).checkOK();
      cb(load.count, steps);
    }
  }

  async installForInstall(packageAID: Uint8Array, appletAID: Uint8Array, instanceAID: Uint8Array, params: Uint8Array) : Promise<APDUResponse> {
    let data = new Uint8Array(packageAID.byteLength + appletAID.byteLength + instanceAID.byteLength + params.byteLength + 9);
    let i = 0;

    data[i++] = packageAID.byteLength;
    data.set(packageAID, i);
    i = i + packageAID.byteLength;
    
    data[i++] = appletAID.byteLength;
    data.set(appletAID, i);
    i = i + packageAID.length;

    data[i++] = instanceAID.byteLength;
    data.set(instanceAID, i);
    i = i + instanceAID.byteLength;

    let privileges = new Uint8Array(0x00);
    data[i++] = privileges.byteLength;
    data.set(privileges, i);
    i++;

    let fullParams = new Uint8Array(2 + params.byteLength);
    fullParams[0] = 0xc9;
    fullParams[1] = params.byteLength;
    fullParams.set(params, 2);
  
    data[i++] = fullParams.byteLength;
    data.set(fullParams, i);
    i++;

    data[i] = 0x00;

    let cmd = new APDUCommand(0x80, GlobalPlatformConstants.INS_INSTALL, GlobalPlatformConstants.INSTALL_FOR_INSTALL_P1, 0, data);
    return this.secureChannel.send(cmd);
  }

  async installNDEFApplet(ndefRecord: Uint8Array) : Promise<APDUResponse> {
    return this.installForInstall(GlobalPlatformConstants.PACKAGE_AID, GlobalPlatformConstants.NDEF_AID, GlobalPlatformConstants.NDEF_INSTANCE_AID, ndefRecord);
  }

  async installKeycardApplet() : Promise<APDUResponse> {
    return this.installForInstall(GlobalPlatformConstants.PACKAGE_AID, GlobalPlatformConstants.KEYCARD_AID, GlobalPlatformConstants.getKeycardInstanceAID(), new Uint8Array(0));
  }

  async installCashApplet(cashData = new Uint8Array(0)) : Promise<APDUResponse> {
    return this.installForInstall(GlobalPlatformConstants.PACKAGE_AID, GlobalPlatformConstants.CASH_AID, GlobalPlatformConstants.CASH_INSTANCE_AID, cashData);
  }
}
