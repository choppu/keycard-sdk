import { BERTLV } from "./ber-tlv"

const TLV_APPLICATION_STATUS_TEMPLATE = 0xa3;

export class ApplicationStatus {
  pinRetryCount: number;
  pukRetryCount: number;
  hasMasterKey: boolean;

  constructor(tlvData: Uint8Array) {
    let tlv = new BERTLV(tlvData);
    tlv.enterConstructed(TLV_APPLICATION_STATUS_TEMPLATE);

    this.pinRetryCount = tlv.readInt();
    this.pukRetryCount = tlv.readInt();
    this.hasMasterKey = tlv.readBoolean();
  }
}