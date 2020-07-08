export namespace GlobalPlatformConstants {
  export const INS_SELECT = 0xa4;
  export const INS_INITIALIZE_UPDATE = 0x50;
  export const INS_EXTERNAL_AUTHENTICATE = 0x82;
  export const INS_DELETE = 0xe4;
  export const INS_INSTALL = 0xe6;
  export const INS_LOAD = 0xe8;
  export const INS_PUT_KEY = 0xd8;

  export const SELECT_P1_BY_NAME = 0x04;
  export const EXTERNAL_AUTHENTICATE_P1 = 0x01;
  export const INSTALL_FOR_LOAD_P1 = 0x02;
  export const INSTALL_FOR_INSTALL_P1 = 0x0c;
  export const LOAD_P1_MORE_BLOCKS = 0x00;
  export const LOAD_P1_LAST_BLOCK = 0x80;

  export const CASH_INSTANCE_AID = new Uint8Array([0xa0, 0x00, 0x00, 0x08, 0x04, 0x00, 0x01, 0x03, 0x01]);
  export const NDEF_INSTANCE_AID = new Uint8Array([0xd2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01]);
  export const PACKAGE_AID = new Uint8Array([0xa0, 0x00, 0x00, 0x08, 0x04, 0x00, 0x01]);
  export const KEYCARD_AID = new Uint8Array([0xa0, 0x00, 0x00, 0x08, 0x04, 0x00, 0x01, 0x01]);

  export const NDEF_AID = new Uint8Array ([0xa0, 0x00, 0x00, 0x08, 0x04, 0x00, 0x01, 0x02]);
  export const CASH_AID = new Uint8Array([0xa0, 0x00, 0x00, 0x08, 0x04, 0x00, 0x01, 0x03]);

  export const KEYCARD_DEFAULT_INSTANCE_IDX = 1;

  export function getKeycardInstanceAID(instanceIdx = KEYCARD_DEFAULT_INSTANCE_IDX) : Uint8Array {
    if (instanceIdx < 0x01 || instanceIdx > 0xff) {
      throw new Error("Error: The instance index must be between 1 and 255");
    }

    let instanceAID = new Uint8Array(KEYCARD_AID.byteLength + 1);
    instanceAID.set(KEYCARD_AID, 0);
    instanceAID[KEYCARD_AID.length] = instanceIdx;
    
    return instanceAID;
  }
}