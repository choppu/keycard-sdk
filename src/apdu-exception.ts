export class APDUException extends Error {
  sw: number;

  constructor(message: string, sw = 0) {
    if(sw) {
      super(message + ", 0x" + sw.toString(16));
    } else {
      super(message);
    }

    this.sw = sw;
  }
}

export class WrongPINException extends APDUException {
  retryAttempts: number;

  constructor(retryAttempts: number) {
    super("Error: Wrong PIN");
    this.retryAttempts = retryAttempts;
  }

  getRetryAttempts() : number {
    return this.retryAttempts;
  }
}

export class CardIOError extends Error {
  constructor(err: any) {
    super("CardIO Error: " + err);
  }
}