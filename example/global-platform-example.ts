import { Keycard } from "../src/index"
import { KeycardGlobalPlatform } from "../src/keycard-global-platform"

const pcsclite = require("@pokusew/pcsclite");
const pcsc = pcsclite();
const process = require("process");

function hx(arr: Uint8Array) : string {
  return Buffer.from(arr).toString('hex');
}

function createGlobalPlatformChannel(): any {
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
            let cmdSet = new KeycardGlobalPlatform.GlobalPlatformCommandset(channel);
            console.log("Selecting card");
            (await cmdSet.select()).checkOK();
            console.log("Opening Global Platform Secure Channel");
            await cmdSet.openSecureChannel();
            console.log("Secure Channel opened");
            (await cmdSet.deleteNDEFInstance()).checkSW([0x9000, 0x6a88]);
            console.log("NDEF Instance deleted");
            process.exit(0);
          } catch (err) {
            console.log(err);
            process.exit(0);
          }
        });
      }
    });
  });
}

createGlobalPlatformChannel();