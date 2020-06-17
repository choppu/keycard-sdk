import { CardChannel } from "./card-channel"
import { APDUResponse } from "./apdu-response";
import { APDUCommand } from "./apdu-command";
import { CardIOError } from "./apdu-exception"

const pcsclite = require('@pokusew/pcsclite');

export class PCSCCardChannel implements CardChannel {
  cardChannel: any;

  constructor(cardChannel: any) {
    this.cardChannel = cardChannel;
  }

  send(cmd: APDUCommand) : APDUResponse {
    let apduCmd = Buffer.from(cmd.serialize());
    let apduResp;

    this.sendDataAsync(apduCmd)
    .then(function (resp) { 
      apduResp = resp;
     })
    .catch(function (err) {
        throw new CardIOError(err);
    });

    return new APDUResponse(new Uint8Array(apduResp));
  }

  sendDataAsync(cmd: Buffer) : Promise<any> {
    return new Promise(function(resolve,reject) {
      this.cardChannel.transmit(cmd, 32, pcsclite.SCARD_PROTOCOL_T1, function(err, resp) {
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