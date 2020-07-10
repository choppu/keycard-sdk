import { Keycard } from "../src/index"
import { GlobalPlatform } from "../src/global-platform"

const pcsclite = require("@pokusew/pcsclite");
const pcsc = pcsclite();
const process = require("process");
const fs = require("fs");

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
            let cap = fs.readFileSync(process.argv[2]);
            let channel = new Keycard.PCSCCardChannel(reader, protocol);
            let cmdSet = new GlobalPlatform.GlobalPlatformCommandset(channel);
            console.log("Selecting card");
            (await cmdSet.select()).checkOK();
            console.log("Opening Global Platform Secure Channel");
            await cmdSet.openSecureChannel();
            console.log("Secure Channel opened");
            console.log("Deleting the old instances and package (if present)");
            await cmdSet.deleteKeycardInstancesAndPackage();
            console.log("Loading the new package");
            (await cmdSet.loadKeycardPackage(cap, (loadedBlock, blockCount) => console.log("Loaded block " + loadedBlock + "/" + blockCount)));
            console.log("Installing the Keycard Applet");
            (await cmdSet.installKeycardApplet()).checkOK();
            console.log("Installing the NDEF Applet");
            (await cmdSet.installNDEFApplet(new Uint8Array(0))).checkOK();
            console.log("Installing the Cash Applet");
            (await cmdSet.installCashApplet()).checkOK();
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