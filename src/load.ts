const BLOCK_SIZE = 247;

export class Load {
  offset: number;
  count: number;
  fullData: Uint8Array;

  constructor(cap: Uint8Array) {
    this.offset = 0;
    this.count = 0;
  }

  blocksCount() : number {
    return Math.ceil(this.fullData.length / BLOCK_SIZE);
  }

  nextDataBlock() : Uint8Array {
    return;
  }

  hasMore() : boolean {
    return this.offset < this.fullData.length;
  }

}