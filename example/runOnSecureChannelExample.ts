import { Keycard } from "../src/index"
import pcsclite from "@nonth/pcsclite";
import process from "process";
import { TestStorage } from "./test_pairing_storage";
import { PAIRED } from "../src/keycard-manager";
import { Constants } from "../src/constants";
import { Mnemonic } from "../src/mnemonic";
import { Commandset } from "../src/commandset";

const pcsc = pcsclite();

function hx(arr: Uint8Array) : string {
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
            let pairingStorage = new TestStorage();
            
            if(channel) {
              let keycardManager = new Keycard.KeycardManager(pairingStorage);
              let authCert = new Uint8Array([0x02, 0x9a, 0xb9, 0x9e, 0xe1, 0xe7, 0xa7, 0x1b, 0xdf, 0x45, 0xb3, 0xf9, 0xc5, 0x8c, 0x99, 0x86, 0x6f, 0xf1, 0x29, 0x4d, 0x2c, 0x1e, 0x30, 0x4e, 0x22, 0x8a, 0x86, 0xe1, 0x0c, 0x33, 0x43, 0x50, 0x1c]);

              let mnemonicResponse = await keycardManager.runOnSecureChannel(
                channel, 
                PAIRED, 
                {newPin: '123456', skipVerificationUID: [], cardPublicKeys: [authCert]},
                async(cmdSet: Commandset) => (await cmdSet.generateMnemonic(Constants.GENERATE_MNEMONIC_12_WORDS)).checkOK().data
              );
              
              if(mnemonicResponse.status == 'error') {
                console.log(mnemonicResponse.data.message);
              }
              
              let mn = new Mnemonic(mnemonicResponse.data.data);
              mn.fetchBIP39EnglishWordlist();

              let keyResponse = await keycardManager.runOnSecureChannel(
                channel, 
                PAIRED, 
                {pin: '123456'},
                async(cmdSet: Commandset) => (await cmdSet.loadBIP32KeyPair(mn.toBIP32KeyPair())).checkOK()
              );

              await keycardManager.runOnSecureChannel(
                channel, 
                PAIRED, 
                {pin: '123456'},
                async(cmdSet: Commandset) => await cmdSet.autoUnpair()
              );


              console.log(mnemonicResponse);
              console.log(hx(keyResponse.data.data.data));
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