import { CardChannel } from "./card-channel"
import { APDUResponse } from "./apdu-response";
import { APDUCommand } from "./apdu-command";
import { CardIOError } from "./apdu-exception"

const pcsclite = require('@pokusew/pcsclite');

export class PCSCCardChannel implements CardChannel {
  cardChannel: any;
  protocol: number;

  constructor(cardChannel: any, protocol: number) {
    this.cardChannel = cardChannel;
    this.protocol = protocol;
  }

  async send(cmd: APDUCommand) : Promise<APDUResponse> {
    let apduCmd = Buffer.from(cmd.serialize());
    let apduResp;

    try {
      apduResp = await this.sendDataAsync(this.cardChannel, this.protocol, apduCmd)  
    } catch(err) {
      throw new CardIOError(err);
    };
    
    return new APDUResponse(new Uint8Array(apduResp));
  }

  sendDataAsync(channel: any, protocol: number, cmd: Buffer) : Promise<any> {
    return new Promise(function(resolve,reject) {
      channel.transmit(cmd, 255, protocol, function(err, resp) {
        if (err) {
          reject(err);
        } else {
          resolve(resp);
        }
      });
    });
  }

  isConnected() : boolean {
    return true;
  }

}