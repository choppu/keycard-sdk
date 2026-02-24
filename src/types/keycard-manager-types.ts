import { ApplicationInfo } from "../application-info.ts";

export type KeycardManagerArgs = {
  skipVerificationUID?: Uint8Array[];
  cardPublicKeys?: Uint8Array[];
  newPin?: string;
  duressPin?: string;
  newPuk?: string;
  newPairingPassword?: string;
  pin?: string;
  pairingPassword?: string;
  mnemonic?: string;
}

export type KeycardManagerResponse = {
  status: string;
  data: any;
}

export type KeycardManagerErrorData = {
  type: number;
  message: string;
  cardInfo: ApplicationInfo;
  cardAuthentic?: boolean;
  paired?: boolean;
}