import { CardChannel } from "./card-channel"
import { APDUResponse } from "./apdu-response";
import { APDUCommand } from "./apdu-command";
import { INS_SIGN } from "./commandset"

const CASH_INSTANCE_AID = new Uint8Array([0xa0, 0x00, 0x00, 0x08, 0x04, 0x00, 0x01, 0x03, 0x01]);

export class CashCommandset {
  apduChannel: CardChannel;

  constructor(apduChannel: CardChannel) {
    this.apduChannel = apduChannel;
  }

  select() : APDUResponse {
    let selectApplet = new APDUCommand(0x00, 0xA4, 4, 0, CASH_INSTANCE_AID);
    return this.apduChannel.send(selectApplet);
  }

  sign(data: Uint8Array) : APDUResponse {
    let sign = new APDUCommand(0x80, INS_SIGN, 0x00, 0x00, data);
    return this.apduChannel.send(sign);
  }
}