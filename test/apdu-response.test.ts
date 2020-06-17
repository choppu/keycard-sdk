import { APDUResponse } from "../src/apdu-response";
import { APDUException, WrongPINException } from "../src/apdu-exception"

const apdu1B = new Uint8Array([0x90]);
const apdu = new Uint8Array([0x06, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x07, 0x00, 0x90, 0x00]);
const apduErr = new Uint8Array([0x06, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x07, 0x00, 0x88, 0x00]);
const apduSecCondNotSatisfied = new Uint8Array([0x9f, 0x7f, 0x2a, 0x47, 0x90, 0x50, 0x40, 0x47, 0x91, 0x81, 0x02, 0x31, 0x00, 0x69, 0x82]);
const apduAuthMethodBlocked = new Uint8Array([0x9f, 0x7f, 0x2a, 0x47, 0x90, 0x50, 0x40, 0x47, 0x91, 0x81, 0x02, 0x31, 0x00, 0x69, 0x83]);
const apduWrongPinMask = new Uint8Array([0x9f, 0x7f, 0x2a, 0x47, 0x90, 0x50, 0x40, 0x47, 0x91, 0x81, 0x02, 0x31, 0x00, 0x63, 0xc0]);

const apduResp = new APDUResponse(apdu);
const apduErrResp = new APDUResponse(apduErr);
const apduSecCondNotSatisfiedResp = new APDUResponse(apduSecCondNotSatisfied);
const apduAuthMethodBlockedRes = new APDUResponse(apduAuthMethodBlocked);
const apduWrongPinMaskRes = new APDUResponse(apduWrongPinMask);

const apduCodes = [0x9000, 0x8500, 0x77ab, 0xcc10];
const apduCode = 0x8800;

test('Check if APDUResponse function throws error', () => {
  expect(() => new APDUResponse(apdu1B)).toThrowError(new Error("APDU response must be at least 2 bytes"));
  expect(() => new APDUResponse(apdu)).not.toThrow(new Error("APDU response must be at least 2 bytes"));
});

test('Check APDUResponse isOK function', () => {
  expect(apduResp.isOK()).toBe(true);
  expect(apduErrResp.isOK()).toBe(false);
});

test('Check APDUResponse checkSW function', () => {
  expect(apduResp.checkSW(apduCodes)).toMatchObject(new APDUResponse(apdu));
  expect(apduErrResp.checkSW(apduCode)).toMatchObject(new APDUResponse(apduErr));

  expect(() => apduErrResp.checkSW(apduCodes, "No match found in the codes array")).toThrowError(new APDUException("No match found in the codes array", apduErrResp.sw));
  expect(() => apduErrResp.checkSW(apduCodes, "No match found in the codes array")).not.toThrowError(new APDUException("Error", apduErrResp.sw));
  expect(() => apduSecCondNotSatisfiedResp.checkSW(apduCodes)).toThrowError(new APDUException("Security condition not satisfied", apduSecCondNotSatisfiedResp.sw));
  expect(() => apduAuthMethodBlockedRes.checkSW(apduCodes)).toThrowError(new APDUException("Authentication method blocked", apduAuthMethodBlockedRes.sw));
  expect(() => apduWrongPinMaskRes.checkSW(apduCodes)).toThrowError(new APDUException("Unexpected error SW", apduWrongPinMaskRes.sw));

  expect(apduResp.checkOK()).toMatchObject(new APDUResponse(apdu));
  expect(() => apduErrResp.checkOK()).toThrowError(new APDUException("Unexpected error SW", apduErrResp.sw));

  expect( apduResp.checkAuthOK()).toMatchObject(new APDUResponse(apdu));
  expect(() => apduWrongPinMaskRes.checkAuthOK()).toThrowError(new WrongPINException(apduWrongPinMaskRes.sw2 & 0x0f));
  expect(() => apduResp.checkAuthOK()).not.toThrowError(new WrongPINException(apduWrongPinMaskRes.sw2 & 0x0f));
});