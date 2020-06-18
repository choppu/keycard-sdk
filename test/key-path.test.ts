import { KeyPath } from "../src/key-path"
import { Constants } from "../src/constants"

const path = "m/44'/0'/0'/0/0";
const parentPath = "../44'/0'/0'/0/0";
const currentPath = "./44'/0'/0'/0/0";
const defPath = "44'/0'/0'/0/0"
const pathBytes = new Uint8Array([0x80, 0x00, 0x00, 0x2c, 0x80, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
const keypath = new KeyPath(path);
const parentKeypath = new KeyPath(parentPath);
const currentKeypath = new KeyPath(currentPath);
const defKeypath = new KeyPath(defPath);
const keypathFromBytes = new KeyPath(pathBytes, Constants.DERIVE_SOURCE.deriveP1SourceMaster);

test('KeyPath constructor function', () => {
  expect(keypath).toMatchObject(keypathFromBytes);
  expect(currentKeypath.toString()).toEqual(currentPath);
  expect(parentKeypath.toString()).toEqual(parentPath);
  expect(keypathFromBytes.toString()).toEqual(path);
  expect(defKeypath.toString()).toEqual(currentPath);
});