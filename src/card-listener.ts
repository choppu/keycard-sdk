import { CardChannel } from "./card-channel.ts"

export interface CardListener {
  onConnected: (channel: CardChannel) => void;
  onDisconnected: () => void;
}