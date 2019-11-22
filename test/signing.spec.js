var expect = require("chai").expect;
var keyStore = require("../lib/keystore");
var fixtures = require("./fixtures/keystore");
var { Transaction } = require("ethereumjs-tx");
var util = require("ethereumjs-util");
var signing = require("../lib/signing");

describe("Signing", function() {
  describe("signTx", function() {
    it("signs a transaction deterministically", function(done) {
      var pw = Uint8Array.from(fixtures.valid[0].pwDerivedKey);
      var fixture = fixtures.valid[0];
      keyStore.createVault(
        {
          password: fixture.password,
          seedPhrase: fixture.mnSeed,
          salt: fixture.salt,
          hdPathString: fixture.hdPathString
        },
        function(err, ks) {
          ks.generateNewAddress(pw);
          var addr = ks.getAddresses()[0];
          expect(addr).to.equal(fixtures.valid[0].ethjsTxParams.from);

          var tx = new Transaction(fixtures.valid[0].ethjsTxParams);
          var rawTx = tx.serialize().toString("hex");
          expect(rawTx).to.equal(fixtures.valid[0].rawUnsignedTx);

          var signedTx0 = signing.signTx(ks, pw, rawTx, addr);
          expect(signedTx0).to.equal(fixtures.valid[0].rawSignedTx);
          done();
        }
      );
    });

    it("Correctly handles a 31 byte key from bitcore", function(done) {
      var secretSeed =
        "erupt consider beyond twist bike enroll you salute weasel emerge divert hundred";

      var hdPath = "m/44'/60'/0'"; //as defined in SLIP44
      var password = "test";

      var fixture = fixtures.valid[0];
      keyStore.createVault(
        {
          password: password,
          seedPhrase: secretSeed,
          salt: "someSalt",
          hdPathString: hdPath
        },
        function(err, keystore) {
          keystore.keyFromPassword(password, function(err, pwDerivedKey) {
            keystore.generateNewAddress(pwDerivedKey, 1); //Generate a new address

            var address = keystore.getAddresses()[0];

            var hexSeedETH = keystore.exportPrivateKey(address, pwDerivedKey);
            var addr0 = keyStore._computeAddressFromPrivKey(hexSeedETH);
            expect(address).to.equal("0x" + addr0);

            var tx = new Transaction({
              from: address,
              to: address,
              value: 100000000
            });
            var rawTx = tx.serialize().toString("hex");

            var signedTx = signing.signTx(
              keystore,
              pwDerivedKey,
              rawTx,
              address,
              hdPath
            );
            var expectedTx =
              "f861808080945e2abe3de708923e8425348005ee7fdd77e203cb8405f5e1008025a064a9afc0c98266f72a0771c894996ef2dea73385e88f4dd6d4c89e3e9cbe813aa02af127ff47561e6682b1b56218f7a9630a22f7061dda78d503884466c105eabe";

            expect(signedTx).to.equal(expectedTx);
            done();
          });
        }
      );
    });

    describe("signMsg", function() {
      it("signs a message deterministically", function(done) {
        var pw = Uint8Array.from(fixtures.valid[0].pwDerivedKey);

        var fixture = fixtures.valid[0];
        keyStore.createVault(
          {
            password: fixture.password,
            seedPhrase: fixture.mnSeed,
            salt: fixture.salt,
            hdPathString: fixture.hdPathString
          },
          function(err, ks) {
            ks.generateNewAddress(pw);
            var addr = ks.getAddresses()[0];
            expect(addr).to.equal(fixtures.valid[0].ethjsTxParams.from);

            var msg = "this is a message";

            var signedMsg = signing.signMsg(ks, pw, msg, addr);

            var msgHash = util.addHexPrefix(util.keccak(msg).toString("hex"));

            var signedMsgHash = signing.signMsgHash(ks, pw, msgHash, addr);

            // signedMsg and signedMsgHash have the same signature
            expect(signedMsg.v).to.equal(signedMsgHash.v);
            expect(signedMsg.r.toString()).to.equal(signedMsgHash.r.toString());
            expect(signedMsg.s.toString()).to.equal(signedMsgHash.s.toString());

            var recoveredAddress = signing.recoverAddress(
              msg,
              signedMsg.v,
              signedMsg.r,
              signedMsg.s
            );

            expect(addr).to.equal("0x" + recoveredAddress.toString("hex"));
            var concatSig = signing.concatSig(signedMsg);
            var expectedConcatSig =
              "0x7b518ee144b8facf3f21b1f97a6d1f8aea448934d89cf5570e92bcca4d375ab6080f17400eafad3c5808e064ee56cd45321382040fb299fa028ea3cddf3488151c";

            expect(concatSig).to.equal(expectedConcatSig);

            done();
          }
        );
      });
    });
  });
});
