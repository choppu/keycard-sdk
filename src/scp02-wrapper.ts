import { APDUCommand } from "./apdu-command";
import { CryptoUtils } from "./crypto-utils";
import { GlobalPlatformCrypto } from "./global-platform-crypto";

export class SCP02Wrapper {
  macKey: Uint8Array;
  icv: Uint8Array;

  constructor(macKey: Uint8Array) {
    this.macKey = macKey;
    this.icv = new Uint8Array(8);
  }

  wrap(cmd: APDUCommand): APDUCommand {
    let cla = cmd.cla | 0x04;
    let data = cmd.data;

    let macData = new Uint8Array(data.byteLength + 5);
    macData[0] = cla;
    macData[1] = cmd.ins;
    macData[2] = cmd.p1;
    macData[3] = cmd.p2;
    macData[4] = data.byteLength + 8;
    macData.set(data, 5);

    let icv: Uint8Array;

    if (CryptoUtils.Uint8ArrayEqual(this.icv, new Uint8Array(8))) {
      icv = this.icv;
    } else {
      icv = GlobalPlatformCrypto.encryptICV(this.macKey, this.icv);
    }

    let mac = GlobalPlatformCrypto.macFull3des(this.macKey, GlobalPlatformCrypto.appendDESPadding(macData), icv);
    let newData = new Uint8Array(data.byteLength + mac.byteLength);
    newData.set(data, 0);
    newData.set(mac, data.byteLength);

    let wrapped = new APDUCommand(cla, cmd.ins, cmd.p1, cmd.p2, newData, cmd.needsLE);
    this.icv = mac;

    return wrapped;
  }
}