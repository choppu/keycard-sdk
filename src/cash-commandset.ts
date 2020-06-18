import { CardChannel } from "./card-channel"
import { APDUResponse } from "./apdu-response";
import { APDUCommand } from "./apdu-command";
import { Constants } from "./constants";

const CASH_INSTANCE_AID = new Uint8Array([0xa0, 0x00, 0x00, 0x08, 0x04, 0x00, 0x01, 0x03, 0x01]);

export class CashCommandset {
  apduChannel: CardChannel;

  constructor(apduChannel: CardChannel) {
    this.apduChannel = apduChannel;
  }

  async select() : Promise<APDUResponse> {
    let selectApplet = new APDUCommand(0x00, 0xA4, 4, 0, CASH_INSTANCE_AID);
    return this.apduChannel.send(selectApplet);
  }

  async sign(data: Uint8Array) : Promise<APDUResponse> {
    let sign = new APDUCommand(0x80, Constants.INS_SIGN, 0x00, 0x00, data);
    return this.apduChannel.send(sign);
  }
}