import { BERTLV } from "./ber-tlv.ts"
import { CryptoUtils } from "./crypto-utils.ts"
import { Constants } from "./constants.ts"
import { TLV_CERT } from "./certificate.ts";


const TLV_UID = 0x8f;
const TLV_KEY_UID = 0x8e;
const TLV_CAPABILITIES = 0x8d;
const TLV_STATUS = 0x8c;

const CAPABILITY_SECURE_CHANNEL = 0x01;
const CAPABILITY_KEY_MANAGEMENT = 0x02;
const CAPABILITY_CREDENTIALS_MANAGEMENT = 0x04;
const CAPABILITY_NDEF = 0x08;

const CAPABILITIES_ALL = CAPABILITY_SECURE_CHANNEL | CAPABILITY_KEY_MANAGEMENT | CAPABILITY_CREDENTIALS_MANAGEMENT | CAPABILITY_NDEF;

const APP_STATUS_INITIALIZED = 0x10;
const APP_STATUS_LEE_MODE = 0x20;

export class ApplicationInfo {
  initializedCard: boolean;
  instanceUID!: Uint8Array;
  secureChannelPubKey!: Uint8Array;
  appVersion!: number;
  freePairingSlots!: number;
  keyUID!: Uint8Array;
  capabilities: number;
  appStatus!: number;
  certificateData!: Uint8Array;

  constructor(tlvData: Uint8Array) {
    let tlv = new BERTLV(tlvData);

    if (tlv.nextTagIs(Constants.TLV_PUB_KEY)) {
      this.secureChannelPubKey = tlv.readPrimitive(Constants.TLV_PUB_KEY);
      this.initializedCard = false;
      this.capabilities = CAPABILITY_CREDENTIALS_MANAGEMENT;

      if (this.secureChannelPubKey.length > 0) {
        this.capabilities |= CAPABILITY_SECURE_CHANNEL;
      }

      return;
    }

    tlv.enterConstructed(Constants.TLV_APPLICATION_INFO_TEMPLATE);


    if (tlv.nextTagIs(TLV_UID)) {
      this.instanceUID = tlv.readPrimitive(TLV_UID);
    }

    // secureChannelPubKey (0x80) - present in V1-V3, absent in V4+
    if (tlv.nextTagIs(Constants.TLV_PUB_KEY)) {
      this.secureChannelPubKey = tlv.readPrimitive(Constants.TLV_PUB_KEY);
    }

    this.appVersion = tlv.readInt();

    // appStatud (0x8C) - initialized, lee mode, pin retries
    if (tlv.nextTagIs(TLV_STATUS)) {
      this.appStatus = tlv.readPrimitive(TLV_STATUS)[0];
      this.initializedCard = (this.appStatus & APP_STATUS_INITIALIZED) == APP_STATUS_INITIALIZED;
    } else {
      this.appStatus = APP_STATUS_INITIALIZED;
      this.initializedCard = true;
    }

    // freePairingSlots (INTEGER 0x02) - present in V1-V3, absent in V4+
    if (tlv.nextTagIs(Constants.TLV_INT)) {
      this.freePairingSlots = tlv.readInt();
    }

    this.keyUID = tlv.readPrimitive(TLV_KEY_UID);

    // capabilities (0x8D) - present in V2+
    if (tlv.nextTagIs(TLV_CAPABILITIES)) {
      this.capabilities = tlv.readPrimitive(TLV_CAPABILITIES)[0];
    } else {
      this.capabilities = CAPABILITIES_ALL;
    }

    // Parse certificate - present in V4+
    if (tlv.nextTagIs(TLV_CERT)) {
      this.certificateData = tlv.readPrimitive(TLV_CERT);
    }
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