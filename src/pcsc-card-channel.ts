import { CardChannel } from "./card-channel"
import { APDUResponse } from "./apdu-response";
import { APDUCommand } from "./apdu-command";
import { CardIOError } from "./apdu-exception"
import { CardReader } from "@nonth/pcsclite";
export class PCSCCardChannel implements CardChannel {
  cardChannel: CardReader;
  protocol: number;

  constructor(cardChannel: CardReader, protocol: number) {
    this.cardChannel = cardChannel;
    this.protocol = protocol;
  }

  async send(cmd: APDUCommand) : Promise<APDUResponse> {
    let apduCmd = Buffer.from(cmd.serialize());
    let apduResp;

    try {
      apduResp = await this.sendDataAsync(this.cardChannel, this.protocol, apduCmd)  
    } catch(err: any) {
      throw new CardIOError(err);
    };
    
    return new APDUResponse(new Uint8Array(apduResp));
  }

  sendDataAsync(channel: CardReader, protocol: number, cmd: Buffer) : Promise<Buffer> {
    return new Promise(function(resolve,reject) {
      channel.transmit(cmd, 255, protocol, function(error: Error, response: Buffer) {
        if (error) {
          reject(error);
        } else {
          resolve(response);
        }
      });
    });
  }

  isConnected() : boolean {
    return true;
  }

}