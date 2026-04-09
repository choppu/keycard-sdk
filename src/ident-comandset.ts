import { APDUCommand } from "./apdu-command.ts";
import { APDUResponse } from "./apdu-response.ts";
import { CardChannel } from "./card-channel.ts";
import { Constants } from "./constants.ts";
import { Identifiers } from "./identifiers.ts";

export class IdentCommandset {
  apduChannel!: CardChannel;

  constructor(apduChannel: CardChannel) {
    this.apduChannel = apduChannel;
  }

  select() : Promise<APDUResponse> {
    let selectApplet = new APDUCommand(0x00, 0xA4, 4, 0, Identifiers.IDENT_INSTANCE_AID);
    return this.apduChannel.send(selectApplet);
  }

  storeData(data: Uint8Array) : Promise<APDUResponse> {
    let sign = new APDUCommand(0x80, Constants.INS_STORE_DATA, 0x00, 0x00, data);
    return this.apduChannel.send(sign);
  }
}

export { IdentCommandset as IdentComandset };
