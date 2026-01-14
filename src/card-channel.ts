import { APDUCommand } from "./apdu-command.ts"
import { APDUResponse } from "./apdu-response.ts"
export interface CardChannel {
  send: (cmd: APDUCommand) => Promise<APDUResponse>;
  isConnected: () => boolean;
}