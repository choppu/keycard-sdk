const JSZip = require("jszip");

const BLOCK_SIZE = 247;
const CLA = 0x80;
const INS = 0xe8;
const fileNames = ["Header.cap", "Directory.cap", "Import.cap", "Applet.cap", "Class.cap", "Method.cap", "StaticField.cap", "Export.cap", "ConstantPool.cap", "RefLocation.cap"];

let zip = new JSZip();

export class Load {
  offset: number;
  count: number;
  fullData: Uint8Array;

  constructor() {
    this.offset = 0;
    this.count = 0;
  }

  public static async new(cap: Uint8Array) : Promise<Load> {
    let load = new Load();
    await load.readCap(cap);
    return load;
  } 

  async readCap(cap: Uint8Array) : Promise<void> {
    let zipRead = await zip.loadAsync(cap);
    let appletObj = {};
    let length = 0;
    for (let file in zipRead.files) {
      for(let y = 0; y < fileNames.length; y++) {
        if(file.includes(fileNames[y])) {
          let data = await zipRead.file(file).async("uint8array"); 
          appletObj[fileNames[y]] = data;
          length += data.byteLength;
        }
      }
    }
  
    let result = new Uint8Array(length + 4);
    let offset = 4;
    result[0] = 0xc4;
    result[1] = 0x82;
    result[2] = length >> 8;
    result[3] = length;
  
    for(let i = 0; i < fileNames.length; i++) {
      if (appletObj[fileNames[i]]) {
        result.set(appletObj[fileNames[i]], offset);
        offset += appletObj[fileNames[i]].byteLength;
      }
    }

    this.fullData = result;
  }

  blocksCount() : number {
    return Math.ceil(this.fullData.byteLength / BLOCK_SIZE);
  }

  nextDataBlock() : Uint8Array | null {
    if (this.offset >= this.fullData.byteLength) {
      return null;
    }

    let rangeStart = this.offset;
    let rangeEnd = this.offset + BLOCK_SIZE;
    if (rangeEnd >= this.fullData.byteLength) {
      rangeEnd = this.fullData.byteLength;
    }

    let size = rangeEnd - this.offset;
    this.count++;
    this.offset += size;

    return this.fullData.subarray(rangeStart, rangeEnd);
  }

  hasMore() : boolean {
    return this.offset < this.fullData.byteLength;
  }
}
