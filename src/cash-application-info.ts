import { BERTLV } from "./ber-tlv"
import { TLV_APPLICATION_INFO_TEMPLATE, TLV_PUB_KEY } from "./application-info"
import { CryptoUtils } from "./crypto-utils"

const TLV_PUB_DATA = 0x82;

export class CashApplicationInfo {
  pubKey: Uint8Array;
  pubData: Uint8Array;
  appVersion: number;

  constructor(tlvData: Uint8Array) {
    let tlv = new BERTLV(tlvData);

    tlv.enterConstructed(TLV_APPLICATION_INFO_TEMPLATE);
    this.pubKey = tlv.readPrimitive(TLV_PUB_KEY);
    this.appVersion = tlv.readInt();
    this.pubData = tlv.readPrimitive(TLV_PUB_DATA);
  }

  getAppVersionString() : string {
    return CryptoUtils.getAppVersionString(this.appVersion);
  }
}