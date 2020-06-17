import { CardChannel } from "./card-channel"

export interface CardListener {
  onConnected: (channel: CardChannel) => void;
  onDisconnected: () => void;
}