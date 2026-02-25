import { Keycard } from "../src/index"
import pcsclite from "@nonth/pcsclite";
import process from "process";
import { TestStorage } from "./test_pairing_storage";
import { KManagerError, LOADED, PAIRED } from "../src/keycard-manager";
import { Constants } from "../src/constants";
import { Mnemonic } from "../src/mnemonic";
import { Commandset } from "../src/commandset";
import { KeycardManagerResponse } from "../src/types/keycard-manager-types";

const pcsc = pcsclite();

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
            let pairingStorage = new TestStorage();

            if (channel) {
              const keycardManager = new Keycard.KeycardManager(pairingStorage);
              const authCert = new Uint8Array([0x02, 0x9a, 0xb9, 0x9e, 0xe1, 0xe7, 0xa7, 0x1b, 0xdf, 0x45, 0xb3, 0xf9, 0xc5, 0x8c, 0x99, 0x86, 0x6f, 0xf1, 0x29, 0x4d, 0x2c, 0x1e, 0x30, 0x4e, 0x22, 0x8a, 0x86, 0xe1, 0x0c, 0x33, 0x43, 0x50, 0x1c]);
              const transactionData = new Uint8Array([0xf8, 0x6c, 0x80, 0x85, 0x04, 0xe3, 0xb2, 0x92, 0x00, 0x82, 0x52, 0x4c, 0x94, 0xc3, 0x90, 0xcc, 0x49, 0xa3, 0x27, 0x36, 0xa5, 0x87, 0x33, 0xcf, 0x46, 0xbe, 0x42, 0xf7, 0x34, 0xdd, 0x4f, 0x53, 0xcb, 0x88, 0x0d, 0xe0, 0xb6, 0xb3, 0xa7, 0x64, 0x00, 0x00, 0x01, 0x25, 0xa0, 0x5a, 0xb2, 0xf4, 0x8b, 0xdc, 0x67, 0x52, 0x19, 0x14, 0x40, 0xce, 0x62, 0x08, 0x8b, 0x9e, 0x42, 0xf2, 0x02, 0x15, 0xee, 0x43, 0x05, 0x40, 0x35, 0x79, 0xaa, 0x2e]);
              let response: KeycardManagerResponse;

              response = await keycardManager.runOnSecureChannel(
                channel,
                PAIRED,
                { newPin: '123456', skipVerificationUID: [], cardPublicKeys: [authCert] },
                async (cmdSet: Commandset) => (await cmdSet.generateMnemonic(Constants.GENERATE_MNEMONIC_12_WORDS)).checkOK().data
              );

              if (response.status == 'error') {
                console.log(response.data.message);
                return;
              }

              let cardInfo = response.data.cardInfo;
              console.log(hx(response.data.cbFuncResponse));

              let mn = new Mnemonic(response.data.cbFuncResponse);
              mn.fetchBIP39EnglishWordlist();

              response = await keycardManager.runOnSecureChannel(
                channel,
                PAIRED,
                { pin: '123456' },
                async (cmdSet: Commandset) => {
                  await cmdSet.autoUnpair();
                  await pairingStorage.deletePairing(cardInfo.instanceUID);
                }
              );

              response = await keycardManager.runOnSecureChannel(
                channel,
                PAIRED,
                { pin: '123456', skipVerificationUID: [cardInfo.instanceUID], cardPublicKeys: [] },
                async (cmdSet: Commandset) => {
                  const resp = (await cmdSet.loadBIP32KeyPair(mn.toBIP32KeyPair())).checkOK();
                  await cmdSet.autoUnpair();
                  await pairingStorage.deletePairing(cardInfo.instanceUID);

                  return resp;
                }
              );

              console.log(hx(response.data.cbFuncResponse.data));

              response = await keycardManager.runOnSecureChannel(
                channel,
                LOADED,
                { pin: '123456', pairingPassword: 'KeycardDefaultPairing', skipVerificationUID: [cardInfo.instanceUID], cardPublicKeys: [] },
                async (cmdSet: Commandset) => {
                  let resp = (await cmdSet.signWithPath(transactionData, "m", false)).checkOK();
                  await cmdSet.autoUnpair();
                  await pairingStorage.deletePairing(cardInfo.instanceUID);
                  return resp;
                }
              );

              console.log(response.data.cbFuncResponse);

              process.exit(0);
            }
          } catch (err) {
            console.log(err);

            if (err instanceof KManagerError) {
              console.log(err.cardData);
            }
          }
        });
      }
    });
  });
}

createChannel();