import { APDUCommand } from "./apdu-command";
import { APDUResponse } from "./apdu-response";
import { CardChannel } from "./card-channel";
import { Constants } from "./constants";
import { Identifiers } from "./identifiers";

export class IdentComandset {
  apduChannel: CardChannel;

  constructot(apduChannel: CardChannel) {
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