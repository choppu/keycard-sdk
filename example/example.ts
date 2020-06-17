import { Keycard } from "../src/index"

const pcsclite = require("@pokusew/pcsclite");
const pcsc = pcsclite();
const process = require("process");

const GET_STATUS_P1_APPLICATION = 0x00;
const GET_STATUS_P1_KEY_PATH = 0x01;
const GENERATE_MNEMONIC_12_WORDS = 0x04;

function hx(arr: Uint8Array) : string {
  return Buffer.from(arr).toString('hex');
}

function createChannel(): any {
  pcsc.on('reader', function (reader) {
    reader.on('error', function (err) {
      throw new Error(err);
    });

    reader.on('status', function (status) {
      let changes = reader.state ^ status.state;

      if (!changes) {
        throw new Error("Error");
      }

      if ((changes & reader.SCARD_STATE_PRESENT) && (status.state & reader.SCARD_STATE_PRESENT)) {
        reader.connect({ share_mode: reader.SCARD_SHARE_EXCLUSIVE }, async function (err, protocol) {
          if (err) {
            throw new Error(err);
          }

          try {
            let channel = new Keycard.PCSCCardChannel(reader, protocol);
            let cmdSet = new Keycard.Commandset(channel);
            console.log("Selecting card");
            (await cmdSet.select()).checkOK();

            if (cmdSet.applicationInfo.initializedCard == false) {
              (await cmdSet.init("123456", "123456123456", "KeycardTest")).checkOK();
              (await cmdSet.select()).checkOK();
            }

            console.log("Application Info");
            console.log("InstanceUID: " + hx(cmdSet.applicationInfo.instanceUID));
            console.log("SecureChannel Public Key: " + hx(cmdSet.applicationInfo.secureChannelPubKey));
            console.log("App Version: " + cmdSet.applicationInfo.getAppVersionString());
            console.log("Free pairing slots: " + cmdSet.applicationInfo.freePairingSlots);

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

            console.log("Pairing");
            await cmdSet.autoPair("KeycardTest");

            let pairing = cmdSet.getPairing();
            console.log("Pairing with card is done.");
            console.log("Pairing index: " + pairing.pairingIndex);
            console.log("Pairing key: " + hx(pairing.pairingKey));

            console.log("Open secure channel");
            await cmdSet.autoOpenSecureChannel();

            let status = new Keycard.ApplicationStatus((await cmdSet.getStatus(GET_STATUS_P1_APPLICATION)).checkOK().data);

            console.log("PIN retry counter: " + status.pinRetryCount);
            console.log("PUK retry counter: " + status.pukRetryCount);
            console.log("Has master key: " + status.hasMasterKey);

            let mnemonic = new Keycard.Mnemonic((await cmdSet.generateMnemonic(GENERATE_MNEMONIC_12_WORDS)).checkOK().data);
            mnemonic.fetchBIP39EnglishWordlist();

            console.log("Generated mnemonic phrase: " + mnemonic.toMnemonicPhrase());
            console.log("Binary seed: " + hx(mnemonic.toBinarySeed()));

            console.log("Verify PIN");
            (await cmdSet.verifyPIN("123456")).checkAuthOK();

            if (!status.hasMasterKey) {
              (await cmdSet.loadBIP32KeyPair(mnemonic.toBIP32KeyPair())).checkOK();
            }

            let currentPath = new Keycard.KeyPath((await cmdSet.getStatus(GET_STATUS_P1_KEY_PATH)).checkOK().data);
            console.log("Current key path: " + currentPath);

            if (!(currentPath.toString() === "m/44'/60'/0'/0/0")) {
              (await cmdSet.deriveKey("m/44'/60'/0'/0/0")).checkOK();
              console.log("Derived m/44'/60'/0'/0/0");
            }
            
            let walletPublicKey = Keycard.BIP32KeyPair.fromTLV((await cmdSet.exportCurrentKey(true)).checkOK().data);
            console.log("Wallet public key: " + hx(walletPublicKey.publicKey));
            console.log("Wallet address: " + hx(walletPublicKey.toEthereumAddress()));

            let hash = Keycard.CryptoUtils.stringToUint8Array("thiscouldbeahashintheorysoitisok");
            let signature = new Keycard.RecoverableSignature(hash, (await cmdSet.sign(hash)).checkOK().data);

            console.log("Signed hash: " + hx(hash));
            console.log("Recovery ID: " + signature.recId);
            console.log("Rec address: " + hx(signature.getEthereumAddress()));
            console.log("R: " + hx(signature.r));
            console.log("S: " + hx(signature.s));

            console.log("Unpair");
            await cmdSet.autoUnpair();

            process.exit(0);
          } catch (err) {
            console.log(err);
          }
        });
      }
    });
  });
}

createChannel();