export namespace Constants {
  export const TLV_APPLICATION_INFO_TEMPLATE = 0xa4;
  export const TLV_PUB_KEY = 0x80;
  export const TLV_INT = 0x02;
  export const END_OF_TLV = 0xffffffff;
  export const INS_SIGN = 0xc0;
  export const GET_STATUS_P1_APPLICATION = 0x00;
  export const GET_STATUS_P1_KEY_PATH = 0x01; 
  export const DERIVE_SOURCE = {
    deriveP1SourceMaster: 0x00,
    deriveP1SourceParent: 0x40,
    deriveP1SourceCurrent: 0x80
  }
  export const STORE_DATA_P1_PUBLIC = 0x00;
  export const STORE_DATA_P1_CASH = 0x02;
  export const GENERATE_MNEMONIC_12_WORDS = 0x04;
  export const GENERATE_MNEMONIC_15_WORDS = 0x05;
  export const GENERATE_MNEMONIC_18_WORDS = 0x06;
  export const GENERATE_MNEMONIC_21_WORDS = 0x07;
  export const GENERATE_MNEMONIC_24_WORDS = 0x08;
}