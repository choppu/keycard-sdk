import { APDUCommand } from "./apdu-command.ts";
import { APDUResponse } from "./apdu-response.ts";
import { CardChannel } from "./card-channel.ts";
import { Pairing } from "./pairing.ts";

export interface SecureChannel {
  autoOpenSecureChannel(channel: CardChannel) : Promise<void>;
  autoPair(channel: CardChannel, pairingMode: number, sharedSecret: Uint8Array) : Promise<void>;
  autoUnpair(channel: CardChannel) : Promise<void>;
  unpairOthers(channel: CardChannel) : Promise<void>;
  openSecureChannel(channel: CardChannel, index: number, data: Uint8Array) : Promise<APDUResponse>;
  mutuallyAuthenticate(channel: CardChannel, data?: Uint8Array) : Promise<APDUResponse>;
  pair(channel: CardChannel, p1: number, p2: number, data: Uint8Array) : Promise<APDUResponse>;
  unpair(channel: CardChannel, p1: number) : Promise<APDUResponse>;
   /* For V1: verifies the MAC, decrypts the data, extracts the inner SW. */
   /* For V2: decrypts the AES-CCM payload, extracts the inner APDU data and SW. */
  protectedCommand(cla: number, ins: number, p1: number, p2: number, data: Uint8Array) : APDUCommand;
  transmit(apduChannel: CardChannel, apdu: APDUCommand) : Promise<APDUResponse> ;
  setPairing(pairing: Pairing) : void;
  getPairing() : Pairing | null;
  reset() : void;
}