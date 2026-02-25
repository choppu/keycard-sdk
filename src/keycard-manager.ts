import { bytesToHex as toHex, randomBytes } from '@noble/hashes/utils.js';
import { ApplicationInfo } from "./application-info.ts";
import { CardChannel } from "./card-channel.ts";
import { Commandset } from "./commandset.ts";
import { KeycardManagerArgs, KeycardManagerResponse, KeycardManagerResponseData } from "./types/keycard-manager-types.ts";
import { PairingStorage } from './pairing-storage.ts';
import { CryptoUtils } from './crypto-utils.ts';
import { Certificate } from './certificate.ts';
import { APDUException, WrongPINException } from './apdu-exception.ts';
import { Pairing } from './pairing.ts';
import { ApplicationStatus } from './application-status.ts';
import { Constants } from './constants.ts';
import { BIP32KeyPair } from './bip32key.ts';
import { Mnemonic } from './mnemonic.ts';

export const PAIRED = 0;
export const LOADED = 1;
export const defaultPairingPassword = "KeycardDefaultPairing";

export const CardInitializeError = 0xca17;
export const CardPairingError = 0xca61;
export const CardLoadKeyError = 0xca13;
export const CardAuthenticationError = 0xcaa4;
export const CardPinVerificationError = 0xca91;
export const CardRequiredStateError = 0xca83;

export class KManagerError extends Error {
  cardData: any;

  constructor(message: string, data: any) {
    super(message);
    this.cardData = data;
  }
}

export class KeycardManager {
  pairingStorage: PairingStorage;

  constructor(storage: PairingStorage) {
    this.pairingStorage = storage;
  }

  private generatePIN(): string {
    let hexStr = toHex(randomBytes(3));
    return parseInt(hexStr, 16).toString().substring(0, 6);
  }

  private generatePUK(): string {
    let hexStr = toHex(randomBytes(5));
    return (parseInt(hexStr, 16)).toString();
  }

  private async verifyAuthenticity(cmdSet: Commandset, instanceUID: Uint8Array, skipVerificationUID: Uint8Array[], cardPubKeys: Uint8Array[]): Promise<boolean> {
    if (cardPubKeys.length == 0 && skipVerificationUID.map(uid => uid == instanceUID)) {
      return true;
    }

    try {
      let rawChallenge = CryptoUtils.getRandomBytes(32);
      let data = (await cmdSet.identifyCard(rawChallenge)).checkOK().data;
      let cardPubKey = Certificate.verifyIdentity(rawChallenge, data);

      if (cardPubKey == null) {
        return false;
      }

      if (cardPubKeys) {
        for (let i = 0; i < cardPubKeys.length; i++) {
          if (CryptoUtils.Uint8ArrayEqual(cardPubKeys[i], cardPubKey)) {
            return true;
          }
        }
      }
    } catch (err: any) {
      if (err instanceof APDUException) {
        if (err.sw == 0x6985) {
          return false;
        } else {
          throw (err);
        }
      }
    }

    return false;
  }

  private async tryAutoPair(pairingPassword: string, cmdSet: Commandset, pairingStorage: PairingStorage, uid: Uint8Array): Promise<{ paired: boolean, pairing: string | null }> {
    try {
      await cmdSet.autoPair(pairingPassword);
      let pairing = cmdSet.getPairing().toBase64();

      if (cmdSet.getPairing().pairingIndex != 0xFF) {
        await pairingStorage.putPairing(uid, pairing);
      }

      return { paired: true, pairing: pairing }
    } catch (err: any) {
      return { paired: false, pairing: null };
    }
  }

  async runOnSecureChannel(channel: CardChannel, state: number, args: KeycardManagerArgs, cbFunc: (cmdSet: Commandset) => Promise<any>): Promise<KeycardManagerResponse> {
    let sessionPin: string | undefined;
    let initialized: boolean;
    let cardAuthentic: boolean;
    let paired: boolean;
    let keyLoaded: boolean;
    let pinRetry: number;
    let pukRetry: number;
    let pairing: string;

    let sessionPairingPassword = defaultPairingPassword;

    try {
      let cmdSet = new Commandset(channel);
      let applicationInfo = new ApplicationInfo((await cmdSet.select()).checkOK().data);
      let respData: KeycardManagerResponseData = {} as KeycardManagerResponseData;

      initialized = applicationInfo.initializedCard;
      cardAuthentic = true;
      sessionPin = args.pin || args.newPin;

      respData.cardInfo = applicationInfo;

      if (!initialized) {
        if (!sessionPin) {
          respData.type = CardInitializeError;
          respData.message = "Error: Card initialization failed. PIN is missing.";
          return { status: 'error', data: respData }
        }

        let puk = args.newPuk ? args.newPuk : this.generatePUK();
        sessionPairingPassword = args.newPairingPassword ? args.newPairingPassword : sessionPairingPassword;
        let altPin = args.duressPin ? args.duressPin : this.generatePIN();

        try {
          (await cmdSet.init(sessionPin, puk, sessionPairingPassword, altPin)).checkOK();
          applicationInfo = new ApplicationInfo((await cmdSet.select()).checkOK().data);
          initialized = true;
          respData.cardInfo = applicationInfo;
        } catch (err: any) {
          throw new KManagerError(`Card initialization error. ${err}.`, applicationInfo);
        }
      }

      paired = await this.pairingStorage.getPairing(applicationInfo.instanceUID) != null;
      respData.paired = paired;

      if (!paired) {
        if (!args.skipVerificationUID || !args.cardPublicKeys) {
          respData.type = CardAuthenticationError;
          respData.message = "Error: Card authentication failed. skipVerificationUID and/or cardPublicKeys are missing.";
          return { status: 'error', data: respData };
        }

        cardAuthentic = await this.verifyAuthenticity(cmdSet, applicationInfo.instanceUID, args.skipVerificationUID!, args.cardPublicKeys!);
        respData.cardAuthentic = cardAuthentic;

        if (!cardAuthentic) {
          throw new KManagerError('Card is not authentic.', { data: respData });
        }

        try {
          sessionPairingPassword = args.pairingPassword ? args.pairingPassword : sessionPairingPassword;
          let r = await this.tryAutoPair(sessionPairingPassword, cmdSet, this.pairingStorage, applicationInfo.instanceUID)

          paired = r.paired;
          respData.paired = paired;

          if (r.pairing) {
            pairing = r.pairing;
          }
        } catch (err: any) {
          throw new KManagerError(`Card pairing error. ${err}`, { data: respData });
        }
      }

      try {
        let storedPairing = await this.pairingStorage.getPairing(applicationInfo.instanceUID);

        if (storedPairing) {
          pairing = await this.pairingStorage.getPairing(applicationInfo.instanceUID) as string;
        }

        cmdSet.setPairing(Pairing.fromString(pairing!));
        (await cmdSet.autoOpenSecureChannel());
      } catch (err: any) {
        await this.pairingStorage.deletePairing(applicationInfo.instanceUID);

        if (!args.skipVerificationUID || !args.cardPublicKeys) {
          respData.type = CardAuthenticationError;
          respData.message = "Error opening secure channel. Card authentication failed. skipVerificationUID and/or cardPublicKeys are missing.";
          return { status: 'error', data: respData };
        }

        cardAuthentic = await this.verifyAuthenticity(cmdSet, applicationInfo.instanceUID, args.skipVerificationUID!, args.cardPublicKeys!);

        if (cardAuthentic) {
          let r = await this.tryAutoPair(sessionPairingPassword, cmdSet, this.pairingStorage, applicationInfo.instanceUID);
          paired = r.paired;

          if (r.pairing) {
            pairing = r.pairing;
          }

          if (paired) {
            cmdSet.setPairing(Pairing.fromString(pairing!));
            (await cmdSet.autoOpenSecureChannel());
          } else {
            throw new KManagerError(`Error opening secure channel. ${err}`, { data: respData });
          }
        } else {
          throw new KManagerError(`Error opening secure channel. ${err}`, { data: respData });
        }
      }

      if (!sessionPin) {
        respData.type = CardPinVerificationError;
        respData.message = "Error: Pin verification error. PIN is missing.";
        return { status: 'error', data: respData };
      }

      let status = new ApplicationStatus((await cmdSet.getStatus(Constants.GET_STATUS_P1_APPLICATION)).checkOK().data);

      pinRetry = status.pinRetryCount;
      pukRetry = status.pukRetryCount;
      respData.pinRetry = pinRetry;
      respData.pukRetry = pukRetry;

      try {
        (await cmdSet.verifyPIN(sessionPin)).checkAuthOK();
      } catch (err: any) {
        if (err instanceof WrongPINException) {
          pinRetry--;
          respData.pinRetry = pinRetry;
        }

        throw new KManagerError(`Error verifying PIN. ${err}`, { data: respData });
      }

      if (state == PAIRED) {
        try {
          respData.cbFuncResponse = await cbFunc(cmdSet);
          return { status: 'success', data: respData };
        } catch (err: any) {
          throw new KManagerError(`Error executing callback function. ${err}`, { data: respData });
        }
      } else if (state == LOADED) {
        keyLoaded = new ApplicationStatus((await cmdSet.getStatus(Constants.GET_STATUS_P1_APPLICATION)).checkOK().data).hasMasterKey;

        if (!keyLoaded) {
          if (!args.mnemonic || args.mnemonic.length == 0) {
            respData.type = CardLoadKeyError;
            respData.message = "Error: Load key error. Mnemonic is missing.";
            return { status: 'error', data: respData };
          }

          try {
            let keyPair = BIP32KeyPair.fromBinarySeed(Mnemonic.toBinarySeed(args.mnemonic));
            (await cmdSet.loadBIP32KeyPair(keyPair)).checkOK();
            keyLoaded = true;
          } catch (err: any) {
            throw new KManagerError(`Error loading key. ${err}`, { data: respData });

          }
        }

        try {
          respData.cbFuncResponse = await cbFunc(cmdSet);
          return { status: 'success', data: respData };
        } catch (err: any) {
          throw new KManagerError(`Error executing callback function. ${err}`, { data: respData });
        }
      }

      respData.type = CardRequiredStateError;
      respData.message = `Error: Can't execute callback function. Card state must be PAIRED or LOADED. Requested state - ${state}`;
      return { status: 'error', data: respData };
    } catch (err: any) {
      throw (err);
    }
  }
}
