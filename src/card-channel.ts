import { APDUCommand } from "./apdu-command"
import { APDUResponse } from "./apdu-response"
export interface CardChannel {
  send: (cmd: APDUCommand) => Promise<APDUResponse>;
  isConnected: () => boolean;
}