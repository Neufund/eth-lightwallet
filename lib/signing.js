const { Transaction } = require("ethereumjs-tx");
const util = require("ethereumjs-util");
const { Message, PrivateKey } = require("bitcore-lib");
const Mnemonic = require("bitcore-mnemonic");

const signTx = (keystore, pwDerivedKey, rawTx, signingAddress) => {
  if (!keystore.isDerivedKeyCorrect(pwDerivedKey)) {
    throw new Error("Incorrect derived key!");
  }

  const txCopy = new Transaction(rawTx);

  let privKey = keystore.exportPrivateKey(signingAddress, pwDerivedKey);

  txCopy.sign(new Buffer(privKey, "hex"));
  privKey = "";

  return txCopy.serialize().toString("hex");
};

const signMsg = (keystore, pwDerivedKey, rawMsg, signingAddress) => {
  if (!keystore.isDerivedKeyCorrect(pwDerivedKey)) {
    throw new Error("Incorrect derived key!");
  }

  const msgHash = util.addHexPrefix(util.keccak(rawMsg).toString("hex"));
  return signMsgHash(keystore, pwDerivedKey, msgHash, signingAddress);
};

const signMsgHash = (keystore, pwDerivedKey, msgHash, signingAddress) => {
  if (!keystore.isDerivedKeyCorrect(pwDerivedKey)) {
    throw new Error("Incorrect derived key!");
  }

  signingAddress = util.stripHexPrefix(signingAddress);

  const privKey = keystore.exportPrivateKey(signingAddress, pwDerivedKey);

  return util.ecsign(
    new Buffer(util.stripHexPrefix(msgHash), "hex"),
    new Buffer(privKey, "hex")
  );
};

const recoverAddress = (rawMsg, v, r, s) => {
  const msgHash = util.keccak(rawMsg);

  return util.pubToAddress(util.ecrecover(msgHash, v, r, s));
};

const concatSig = signature => {
  let v = signature.v;
  let r = signature.r;
  let s = signature.s;
  r = util.fromSigned(r);
  s = util.fromSigned(s);
  v = util.bufferToInt(v);
  r = util.setLengthLeft(util.toUnsigned(r), 32).toString("hex");
  s = util.setLengthLeft(util.toUnsigned(s), 32).toString("hex");
  v = util.stripHexPrefix(util.intToHex(v));
  return util.addHexPrefix(r.concat(s, v).toString("hex"));
};

const signTxWithSeed = (mnemonic, msg) => {
  const mnemoniciInstance = new Mnemonic(mnemonic);
  const privateKeyInstance = new PrivateKey(mnemoniciInstance.toHDPrivateKey());
  const messageInstance = new Message(msg);
  return messageInstance.sign(privateKeyInstance);
};

module.exports = {
  concatSig,
  recoverAddress,
  signMsgHash,
  signMsg,
  signTx,
  signTxWithSeed
};
