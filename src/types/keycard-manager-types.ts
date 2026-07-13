import { ApplicationInfo } from "../application-info.ts";

export type KeycardManagerArgs = {
  skipVerificationUID?: Uint8Array[];
  caPublicKeys?: Uint8Array[];
  newPin?: string;
  duressPin?: string;
  newPuk?: string;
  newPairingPassword?: string | Uint8Array;
  pin?: string;
  pairingPassword?: string | Uint8Array;
  mnemonic?: string;
}

export type KeycardManagerResponse = {
  status: string;
  data: any;
}

export type KeycardManagerResponseData = {
  type?: number;
  message?: string;
  cardInfo: ApplicationInfo;
  cardAuthentic?: boolean;
  paired?: boolean;
  pinRetry?: number;
  pukRetry?: number;
  cbFuncResponse?: any;
}