import { BERTLV, END_OF_TLV } from "./ber-tlv"
import { CryptoUtils } from "./crypto-utils"

export const TLV_APPLICATION_INFO_TEMPLATE = 0xa4;
export const TLV_PUB_KEY = 0x80;
const TLV_UID = 0x8f;
const TLV_KEY_UID = 0x8e;
const TLV_CAPABILITIES = 0x8d;

const CAPABILITY_SECURE_CHANNEL = 0x01;
const CAPABILITY_KEY_MANAGEMENT = 0x02;
const CAPABILITY_CREDENTIALS_MANAGEMENT = 0x04;
const CAPABILITY_NDEF = 0x08;

const CAPABILITIES_ALL = CAPABILITY_SECURE_CHANNEL | CAPABILITY_KEY_MANAGEMENT | CAPABILITY_CREDENTIALS_MANAGEMENT | CAPABILITY_NDEF;

export class ApplicationInfo {
  initializedCard: boolean;
  instanceUID: Uint8Array;
  secureChannelPubKey: Uint8Array;
  appVersion: number;
  freePairingSlots: number;
  keyUID: Uint8Array;
  capabilities: number;

  constructor(tlvData: Uint8Array) {
    let tlv = new BERTLV(tlvData);

    let topTag = tlv.readTag();
    tlv.unreadLastTag();

    if (topTag == TLV_PUB_KEY) {
      this.secureChannelPubKey = tlv.readPrimitive(TLV_PUB_KEY);
      this.initializedCard = false;
      this.capabilities = CAPABILITY_CREDENTIALS_MANAGEMENT;

      if (this.secureChannelPubKey.length > 0) {
        this.capabilities |= CAPABILITY_SECURE_CHANNEL;
      }

      return;
    }

    tlv.enterConstructed(TLV_APPLICATION_INFO_TEMPLATE);
    this.instanceUID = tlv.readPrimitive(TLV_UID);
    this.secureChannelPubKey = tlv.readPrimitive(TLV_PUB_KEY);
    this.appVersion = tlv.readInt();
    this.freePairingSlots = tlv.readInt();
    this.keyUID = tlv.readPrimitive(TLV_KEY_UID);

    if (tlv.readTag() != END_OF_TLV) {
      tlv.unreadLastTag();
      this.capabilities = tlv.readPrimitive(TLV_CAPABILITIES)[0];
    } else {
      this.capabilities = CAPABILITIES_ALL;
    }

    this.initializedCard = true;
  }

  hasMasterKey() : boolean {
    return this.keyUID.length != 0;
  }

  getAppVersionString() : string {
    return CryptoUtils.getAppVersionString(this.appVersion);
  }

  hasSecureChannelCapability() : boolean {
    return (this.capabilities & CAPABILITY_SECURE_CHANNEL) == CAPABILITY_SECURE_CHANNEL;
  }

  hasKeyManagementCapability() : boolean {
    return (this.capabilities & CAPABILITY_KEY_MANAGEMENT) == CAPABILITY_KEY_MANAGEMENT;
  }

  hasCredentialsManagementCapability() : boolean {
    return (this.capabilities & CAPABILITY_CREDENTIALS_MANAGEMENT) == CAPABILITY_CREDENTIALS_MANAGEMENT;
  }

  hasNDEFCapability() : boolean {
    return (this.capabilities & CAPABILITY_NDEF) == CAPABILITY_NDEF;
  }
}