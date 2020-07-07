import { CardChannel } from "./card-channel";
import { SCP02Channel } from "./SCP02-channel";
import { SCP02Keys } from "./scp02-keys";
import { APDUResponse } from "./apdu-response";
import { APDUCommand } from "./apdu-command";
import { GlobalPlatformConstants } from "./global-platform-constants";
import { SCP02Session } from "./scp02-session";
import { APDUException } from "./apdu-exception";

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

  
}