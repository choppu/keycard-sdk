import { Keycard } from "../src/index"

const pcsclite = require("@pokusew/pcsclite");
const pcsc = pcsclite();

function createChannel(): any {
  pcsc.on('reader', function(reader) {
    reader.on('error', function(err) {
      throw new Error(err);
    });

    reader.on('status', function(status) {
      let changes = reader.state ^ status.state;

      if (!changes) {
        throw new Error("Error");
      }

      if ((changes & reader.SCARD_STATE_PRESENT) && (status.state & reader.SCARD_STATE_PRESENT)) {
        reader.connect({ share_mode: reader.SCARD_SHARE_EXCLUSIVE }, async function(err, protocol) {
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
            
            console.log("Pairing");
            await cmdSet.autoPair("KeycardTest");
            
            console.log("Open secure channel");
            await cmdSet.autoOpenSecureChannel();
            
            console.log("Verify PIN");
            (await cmdSet.verifyPIN("123456")).checkAuthOK();
           
            console.log("Unpair");
            await cmdSet.autoUnpair();
          } catch(err) {
            console.log(err);
          }
        });
      }
    });
  });
}

createChannel();