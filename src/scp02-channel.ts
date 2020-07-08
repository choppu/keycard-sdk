import { CardChannel } from "./card-channel";
import { SCP02Wrapper } from "./scp02-wrapper";
import { SCP02Keys } from "./scp02-keys";
import { SCP02Session } from "./scp02-session";
import { APDUResponse } from "./apdu-response";
import { APDUException } from "./apdu-exception";
import { Constants } from "./constants"
import { GlobalPlatformCrypto } from "./global-platform-crypto";
import { APDUCommand } from "./apdu-command";

const DERIVATION_PURPOSE_ENC = new Uint8Array([0x01, 0x82]);
const DERIVATION_PURPOSE_MAC = new Uint8Array([0x01, 0x01]);
const DERIVATION_PURPOSE_DEK = new Uint8Array([0x01, 0x81]);

export class SCP02Channel {
  apduChannel: CardChannel;
  wrapper: SCP02Wrapper;

  constructor(apduChannel: CardChannel, scp02Keys: SCP02Keys) {
    this.apduChannel = apduChannel;
    this.wrapper = new SCP02Wrapper(scp02Keys.macKey);
  }

  async send(apduCmd: APDUCommand) : Promise<APDUResponse> {
    let wrappedAPDUCommand = this.wrapper.wrap(apduCmd);
    return this.apduChannel.send(wrappedAPDUCommand);
  }

  static verifyChallenge(hostChallenge: Uint8Array, scp02Keys: SCP02Keys, apduResp: APDUResponse) : SCP02Session {
    if (apduResp.sw == Constants.SW_SECURITY_CONDITION_NOT_SATISFIED) {
      throw new APDUException("Error: Security condition not satisfied", apduResp.sw);
    }

    if (apduResp.sw == Constants.SW_AUTHENTICATION_METHOD_BLOCKED) {
      throw new APDUException("Error: Authentication method blocked", apduResp.sw);
    }

    let data = apduResp.data;

    if (data.byteLength != 28) {
      throw new APDUException("Error: Wrong data length, expected 28, got " + data.byteLength, apduResp.sw);
    }

    let cardChallenge = data.subarray(12, 20);
    let cardCryptogram = data.subarray(20);
    let seq = data.subarray(12, 14);

    let sessionEncKey = GlobalPlatformCrypto.deriveSCP02SessionKey(scp02Keys.encKey, seq, DERIVATION_PURPOSE_ENC);
    let sessionMacKey = GlobalPlatformCrypto.deriveSCP02SessionKey(scp02Keys.macKey, seq, DERIVATION_PURPOSE_MAC);
    let sessionDekKey = GlobalPlatformCrypto.deriveSCP02SessionKey(scp02Keys.dekKey, seq, DERIVATION_PURPOSE_DEK);

    let sessionKeys = new SCP02Keys(sessionEncKey, sessionMacKey, sessionDekKey);

    let verified = GlobalPlatformCrypto.verifyCryptogram(sessionKeys.encKey, hostChallenge, cardChallenge, cardCryptogram);

    if (!verified) {
      throw new APDUException("Error: Error verifying card cryptogram.");
    }

    return new SCP02Session(sessionKeys, cardChallenge);
  }
}