import { bytesToHex as toHex, randomBytes } from '@noble/hashes/utils.js';
import { ApplicationInfo } from "./application-info.ts";
import { CardChannel } from "./card-channel.ts";
import { Commandset } from "./commandset.ts";
import { KeycardManagerArgs, KeycardManagerResponse } from "./types/keycard-manager-types.ts";
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

  private generatePIN() : string {
    let hexStr = toHex(randomBytes(3));
    return parseInt(hexStr, 16).toString().substring(0, 6);
  }

  private generatePUK() : string {
    let hexStr = toHex(randomBytes(5));
    return (parseInt(hexStr, 16)).toString();
  }

  private async verifyAuthenticity(cmdSet: Commandset, instanceUID: Uint8Array, skipVerificationUID: Uint8Array[], cardPubKeys: Uint8Array[]) : Promise<boolean> {
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
      
      if(cardPubKeys) {
        for (let i = 0; i < cardPubKeys.length; i++) {
          if (CryptoUtils.Uint8ArrayEqual(cardPubKeys[i], cardPubKey)) {
            return true;
          }
        }
      }
    } catch(err: any) {
      if(err instanceof APDUException) {
        if(err.sw == 0x6985) {
          return false;
        } else {
          throw (err);
        }
      }
    }
    
    return false;
  }

  async runOnSecureChannel(channel: CardChannel, state: number, args: KeycardManagerArgs, cbFunc: (cmdSet: Commandset) => Promise<any>) : Promise<KeycardManagerResponse> {
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
      let respData: object = {};

      initialized = applicationInfo.initializedCard;
      cardAuthentic = true;
      sessionPin = args.pin || args.newPin;

      if(!initialized) {
        if(!sessionPin) {
          respData = {
            type: CardInitializeError, 
            message: "Error: Card initialization failed. PIN is missing.",
            cardInfo: applicationInfo,
          }

          return {status: 'error', data: respData}
        }

        let puk = args.newPuk ? args.newPuk : this.generatePUK();
        sessionPairingPassword = args.newPairingPassword ? args.newPairingPassword : sessionPairingPassword;
        let altPin = args.duressPin ? args.duressPin : this.generatePIN();
        
        try {
          (await cmdSet.init(sessionPin, puk, sessionPairingPassword, altPin)).checkOK();
          applicationInfo = new ApplicationInfo((await cmdSet.select()).checkOK().data);
          initialized = true;
        } catch (err: any) {
          throw new KManagerError(`Card initialization error. ${err}.`, applicationInfo);
        }
      }
      
      paired = await this.pairingStorage.getPairing(applicationInfo.instanceUID) != null;

      if(!paired) {
        if(!args.skipVerificationUID || !args.cardPublicKeys) {
          respData = {
            type: CardAuthenticationError, 
            message: "Error: Card authentication failed. skipVerificationUID and/or cardPublicKeys are missing.",
            cardInfo: applicationInfo,
          }

          return {status: 'error', data: respData};
        }
        
        cardAuthentic = await this.verifyAuthenticity(cmdSet, applicationInfo.instanceUID, args.skipVerificationUID!, args.cardPublicKeys!);

        if (!cardAuthentic) {
          throw new KManagerError('Error: Card is not authentic.', { applicationInfo: applicationInfo, authentic: cardAuthentic });
        }
        
        try {
          sessionPairingPassword = args.pairingPassword ? args.pairingPassword : sessionPairingPassword;
          await cmdSet.autoPair(sessionPairingPassword);
          pairing = cmdSet.getPairing().toBase64();

          if(cmdSet.getPairing().pairingIndex != 0xFF) {
            await this.pairingStorage.putPairing(applicationInfo.instanceUID, pairing);
          }

          paired = true;
        } catch (err: any) {
          throw new KManagerError(`Card pairing error. ${err}`, { applicationInfo: applicationInfo, authentic: cardAuthentic });
        }
      }
      
      try {
        let storedPairing = await this.pairingStorage.getPairing(applicationInfo.instanceUID);

        if(storedPairing) {
          pairing = await this.pairingStorage.getPairing(applicationInfo.instanceUID) as string;
        }

        cmdSet.setPairing(Pairing.fromString(pairing!));
        await cmdSet.autoOpenSecureChannel();
      } catch (err: any) {
        throw new KManagerError(`Error opening secure channel. ${err}`, { applicationInfo: applicationInfo, cardAuthentic: cardAuthentic })
      }
      

      if(!sessionPin) {
        respData = {
          type: CardPinVerificationError, 
          message: "Error: Pin verification error. PIN is missing.",
          cardInfo: applicationInfo,
          cardAuthentic: cardAuthentic
        }
        
        return {status: 'error', data: respData};
      }

      
      let status = new ApplicationStatus((await cmdSet.getStatus(Constants.GET_STATUS_P1_APPLICATION)).checkOK().data);

      pinRetry = status.pinRetryCount;
      pukRetry = status.pukRetryCount;

      try {
        (await cmdSet.verifyPIN(sessionPin)).checkAuthOK();
      } catch(err: any) {
        if(err instanceof WrongPINException) {
          pinRetry--;
        }

        throw new KManagerError(`Error verifying PIN. ${err}`, { applicationInfo: applicationInfo, authentic: cardAuthentic, pinRetry: pinRetry, pukRetry: pukRetry })
      }

      if(state == PAIRED) {
        try {
          respData = {
            cardInfo: applicationInfo,
            data: await cbFunc(cmdSet)
          }
        
          return {status: 'success', data: respData};
        } catch (err: any) {
          throw new KManagerError(`Error executing callback function. ${err}`, { applicationInfo: applicationInfo, authentic: cardAuthentic, pinRetry: pinRetry, pukRetry: pukRetry, requestedState: state })
        }
      } else if(state == LOADED) {
        keyLoaded = new ApplicationStatus((await cmdSet.getStatus(Constants.GET_STATUS_P1_APPLICATION)).checkOK().data).hasMasterKey;

        if(!keyLoaded) {
          if(!args.mnemonic || args.mnemonic.length == 0) {
            respData = {
              type: CardLoadKeyError, 
              message: "Error: Load key error. Mnemonic is missing.",
              cardInfo: applicationInfo,
            }
      
            return {status: 'error', data: respData};
          }

          try {
            let keyPair = BIP32KeyPair.fromBinarySeed(Mnemonic.toBinarySeed(args.mnemonic));
            (await cmdSet.loadBIP32KeyPair(keyPair)).checkOK();
            keyLoaded = true;
          } catch (err: any) {
            throw new KManagerError(`Error loading key. ${err}`, { applicationInfo: applicationInfo, authentic: cardAuthentic, pinRetry: pinRetry, pukRetry: pukRetry, requestedState: state, keyLoaded: keyLoaded })

          }
        }

        try {
          respData = {
            cardInfo: applicationInfo,
            data: await cbFunc(cmdSet)
          }
        
          return {status: 'success', data: respData};
        } catch (err: any) {
          throw new KManagerError(`Error executing callback function. ${err}`, { applicationInfo: applicationInfo, authentic: cardAuthentic, pinRetry: pinRetry, pukRetry: pukRetry, requestedState: state })
        }
      }
      
      respData = {
        type: CardRequiredStateError, 
        message: `Error: Can't execute callback function. Card state must be PAIRED or LOADED. Requested state - ${state}`,
        cardInfo: applicationInfo
      }
      
      return {status: 'error', data: respData};
    } catch (err: any) {
      throw(err);
    }
  }
}
