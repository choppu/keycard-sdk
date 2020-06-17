import {APDUException, WrongPINException} from "./apdu-exception"

const SW_OK = 0x9000;
const SW_SECURITY_CONDITION_NOT_SATISFIED = 0x6982;
const SW_AUTHENTICATION_METHOD_BLOCKED = 0x6983;
const SW_CARD_LOCKED = 0x6283;
const SW_REFERENCED_DATA_NOT_FOUND = 0x6A88;
const SW_CONDITIONS_OF_USE_NOT_SATISFIED = 0x6985; // applet may be already installed
const SW_WRONG_PIN_MASK = 0x63C0;

export class APDUResponse {
  apdu: Uint8Array;
  data: Uint8Array;
  sw: number;
  sw1: number;
  sw2: number;

 private parse(apdu: Uint8Array) : void {
    let length = apdu.byteLength;

    this.sw1 = apdu[length - 2] & 0xff;
    this.sw2 = apdu[length - 1] & 0xff;
    this.sw = (this.sw1 << 8) | this.sw2;
    this.data = new Uint8Array(apdu.slice(0, (length - 2)));
  }

  constructor(apdu: Uint8Array)  {
    if (apdu.byteLength < 2) {
      throw new Error("APDU response must be at least 2 bytes");
    }
    
    this.apdu = apdu;
    this.parse(this.apdu);
  }

  isOK() : boolean {
    return this.sw == SW_OK;
  }

  checkSW(codes: number|number[], message = null) : APDUResponse {
    if (Array.isArray(codes)) {
      if (codes.includes(this.sw)) {
        return this;
      }
    } else {
      if (this.sw == codes) {
        return this;
      }
    }
    
    if(message) {
      throw new APDUException(message, this.sw);
    } else {
      switch (this.sw) {
        case SW_SECURITY_CONDITION_NOT_SATISFIED:
          throw new APDUException("Security condition not satisfied", this.sw);
        case SW_AUTHENTICATION_METHOD_BLOCKED:
          throw new APDUException("Authentication method blocked", this.sw);
        default:
          throw new APDUException("Unexpected error SW", this.sw);
      }
    }
  }

  checkOK(message = null) : APDUResponse {
    return this.checkSW(SW_OK, message);
  }

  checkAuthOK() : APDUResponse {
    if ((this.sw & SW_WRONG_PIN_MASK) == SW_WRONG_PIN_MASK) {
      throw new WrongPINException(this.sw2 & 0x0F);
    } else {
      return this.checkOK();
    }
  }
}