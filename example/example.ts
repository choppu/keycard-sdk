import { Buffer } from "buffer";
import { Keycard } from "../dist/index.js"
import type { RecoverableSignatureProps } from "../dist/types/recoverable-signature-types.js";
import pcsclite from "@nonth/pcsclite";
import process from "process";
import { SIGN_P2_BIP340_SCHNORR } from "../dist/commandset.js";
import { CryptoUtils } from "../dist/crypto-utils.js";

const pcsc = pcsclite();

const caPubKey = new Uint8Array([
  0x02, 0x58, 0x77, 0x22, 0x0a, 0xaa, 0xe6, 0xe5,
  0x4a, 0x6f, 0x97, 0x46, 0x02, 0xd5, 0x99, 0x5c,
  0x0f, 0xe2, 0x4a, 0x3e, 0xa7, 0xdd, 0xab, 0xd8,
  0x64, 0x4b, 0xec, 0x79, 0x5b, 0x9d, 0xa0, 0x07,
  0x43
]);

function hx(arr: Uint8Array): string {
  return Buffer.from(arr).toString('hex');
}

function createChannel(): any {
  pcsc.on('reader', function (reader: any) {
    reader.on('error', function (err: any) {
      throw new Error(err);
    });

    reader.on('status', function (status: any) {
      let changes = reader.state ^ status.state;

      if (!changes) {
        throw new Error("Error");
      }

      if ((changes & reader.SCARD_STATE_PRESENT) && (status.state & reader.SCARD_STATE_PRESENT)) {
        reader.connect({ share_mode: reader.SCARD_SHARE_EXCLUSIVE }, async function (err: any, protocol: any) {
          if (err) {
            throw new Error(err);
          }

          try {
            let channel = new Keycard.PCSCCardChannel(reader, protocol);
            let cmdSet = new Keycard.Commandset(channel, [caPubKey]) as any;

            if (cmdSet) {
              console.log("Selecting card");
              (await cmdSet.select()).checkOK();

              if (cmdSet.applicationInfo.initializedCard == false) {
                (await cmdSet.init("123456", "123456123456", "KeycardDefaultPairing")).checkOK();
                (await cmdSet.select()).checkOK();
              }

              console.log("Application Info");

              if(cmdSet.applicationInfo.appVersion < 0x0400) {
                console.log("InstanceUID: " + hx(cmdSet.applicationInfo.instanceUID));
                console.log("SecureChannel Public Key: " + hx(cmdSet.applicationInfo.secureChannelPubKey));
                console.log("Free pairing slots: " + cmdSet.applicationInfo.freePairingSlots);
              } else {
                console.log("Certificate: " + hx(cmdSet.applicationInfo.certificateData));
              }

              console.log("App Version: " + cmdSet.applicationInfo.getAppVersionString());

              if (cmdSet.applicationInfo.hasMasterKey()) {
                console.log("Key UID: " + hx(cmdSet.applicationInfo.keyUID));
              } else {
                console.log("The card has no master key");
              }

              console.log("Capabilities: " + cmdSet.applicationInfo.capabilities);
              console.log("Has Secure Channel: " + cmdSet.applicationInfo.hasSecureChannelCapability());
              console.log("Has Key Management: " + cmdSet.applicationInfo.hasKeyManagementCapability());
              console.log("Has Credentials Management: " + cmdSet.applicationInfo.hasCredentialsManagementCapability());
              console.log("Has NDEF capability: " + cmdSet.applicationInfo.hasNDEFCapability());
              console.log("Has Factory Reset capability: " + cmdSet.applicationInfo.hasFactoryResetCapability());

              if (cmdSet.applicationInfo.appVersion < 0x0400) {
                console.log("Pairing");
                await cmdSet.autoPair("KeycardDefaultPairing");

                let pairing = cmdSet.getPairing();
                console.log("Pairing with card is done.");
                console.log("Pairing index: " + pairing.pairingIndex);
                console.log("Pairing key: " + hx(pairing.pairingKey));

                console.log("Open secure channel");
              }

              await cmdSet.autoOpenSecureChannel();

              let status = new Keycard.ApplicationStatus((await cmdSet.getStatus(Keycard.Constants.GET_STATUS_P1_APPLICATION)).checkOK().data);

              console.log("PIN retry counter: " + status.pinRetryCount);
              console.log("PUK retry counter: " + status.pukRetryCount);
              console.log("Has master key: " + status.hasMasterKey);

              let mnemonic = new Keycard.Mnemonic((await cmdSet.generateMnemonic(Keycard.Constants.GENERATE_MNEMONIC_12_WORDS)).checkOK().data);
              mnemonic.fetchBIP39EnglishWordlist();

              console.log("Generated mnemonic phrase: " + mnemonic.toMnemonicPhrase());
              console.log("Binary seed: " + hx(mnemonic.toBinarySeed()));

              console.log("Verify PIN");
              (await cmdSet.verifyPIN("000000")).checkAuthOK();

              if (!status.hasMasterKey) {
                (await cmdSet.loadBIP32KeyPair(mnemonic.toBIP32KeyPair())).checkOK();
              }

              let extendedKey = Keycard.BIP32KeyPair.extendedKey((await cmdSet.exportExtendedKey(0, "m/44'/60'/0'/0", false)).checkOK().data);
              console.log("Derived key 0: " + hx(extendedKey.deriveChild(0).publicKey!));
              console.log("Derived key 1: " + hx(extendedKey.deriveChild(1).publicKey!));
              console.log("Derived key 2: " + hx(extendedKey.deriveChild(2).publicKey!));


              let hash = Keycard.CryptoUtils.stringToUint8Array("thiscouldbeahashintheorysoitisok");
              let signature = new Keycard.RecoverableSignature({ hash: hash, tlvData: (await cmdSet.signWithPath(hash, "m/44'/60'/0'/0/1", false)).checkOK().data } as RecoverableSignatureProps);

              console.log("Signed hash: " + hx(hash));
              console.log("Recovery ID: " + signature.recId);
              console.log("Rec address: " + hx(signature.getEthereumAddress()));
              console.log("R: " + hx(signature.r!));
              console.log("S: " + hx(signature.s!));

              if (cmdSet.applicationInfo.appVersion > 0x0400) {
                const schnorrSignature = (await cmdSet.signWithPath(hash, "m/44'/60'/0'/0/1", false, SIGN_P2_BIP340_SCHNORR)).checkOK().data;
                const isValidSig = await CryptoUtils.verifySchnorrSignature(hash, schnorrSignature);

                console.log("Compressed public key - " + hx(CryptoUtils.compressPublicKey(CryptoUtils.extractPublicKeyFromSignature(schnorrSignature))));
                console.log("Signature - " + hx(CryptoUtils.extractSignature(schnorrSignature)));
                console.log(`Is valid schnorr signature - ${isValidSig}`);
              }

              if(cmdSet.applicationInfo.appVersion < 0x0400) {
                console.log("Unpair");
                await cmdSet.autoUnpair();
              }

              process.exit(0);
            }
          } catch (err) {
            console.log(err);
          }
        });
      }
    });
  });
}

createChannel();