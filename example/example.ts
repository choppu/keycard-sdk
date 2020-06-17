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
            await cmdSet.select();
            console.log(cmdSet.applicationInfo);
          } catch(err) {
            console.log(err);
          }
        });
      }
    });
  });
}

createChannel();