const APDU_FIXED_PARAMS_SIZE = 5;

export class APDUCommand {
  cla: number;
  ins: number;
  p1: number;
  p2: number;
  data: Uint8Array;
  needsLE: boolean;

  constructor(cla: number, ins: number, p1: number, p2: number, data: Uint8Array, needsLE = false) {
    this.cla = cla;
    this.ins = ins;
    this.p1 = p1;
    this.p2 = p2;
    this.data = new Uint8Array(data);
    this.needsLE = needsLE;
  }

  serialize() : Uint8Array {
    let apduBufLength = APDU_FIXED_PARAMS_SIZE + this.data.byteLength;
    if (this.needsLE) apduBufLength++;

    let outputArr = new Uint8Array(apduBufLength);
    let i = 0;

    outputArr[i++] = this.cla;
    outputArr[i++] = this.ins;
    outputArr[i++] = this.p1;
    outputArr[i++] = this.p2;
    outputArr[i++] = this.data.byteLength;
    outputArr.set(this.data, i);

    return outputArr;
  }
}