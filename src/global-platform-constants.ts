export namespace GlobalPlatformConstants {
  export const INS_SELECT = 0xa4;
  export const INS_INITIALIZE_UPDATE = 0x50;
  export const INS_EXTERNAL_AUTHENTICATE = 0x82;
  export const INS_GET_DATA = 0xca;
  export const INS_DELETE = 0xe4;
  export const INS_INSTALL = 0xe6;
  export const INS_GET_STATUS = 0xf2;
  export const INS_LOAD = 0xe8;
  export const INS_PUT_KEY = 0xd8;
  export const INS_SET_STATUS = 0xf0;

  export const SELECT_P1_BY_NAME = 0x04;
  export const EXTERNAL_AUTHENTICATE_P1 = 0x01;
  export const GET_DATA_KEY_INFORMATION_TEMPLATE = 0x00e0;
  export const INSTALL_FOR_LOAD_P1 = 0x02;
  export const INSTALL_FOR_INSTALL_P1 = 0x0c;
  export const GET_STATUS_P1_ISD = 0x80;
  export const GET_STATUS_P1_APPLICATIONS = 0x40;
  export const GET_STATUS_P2_TLV = 0x02;
  export const GET_STATUS_P2_NEXT = 0x01;
  export const LOAD_P1_MORE_BLOCKS = 0x00;
  export const LOAD_P1_LAST_BLOCK = 0x80;
  export const SET_STATUS_P1_ISD = 0x80;
  export const SET_STATUS_P1_APPLICATION = 0x40;

  export const CARD_LIFE_CYCLE_INITIALIZED = 0x07;
  export const CARD_LIFE_CYCLE_SECURED = 0x0f;
}