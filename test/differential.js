'use strict';

/**
 * Differential test against runonflux/bitcore-message ec2fb0a with
 * bitcore-lib 8f5453f, installed as the devDependency
 * `bitcore-message-ec2fb0a`.
 *
 * Every check runs the same operation through both and requires identical
 * output: magic hashes, compact signatures byte for byte (with the random
 * nonce fixed), verification results and the error each verification sets.
 */

var crypto = require('crypto');
var path = require('path');
var expect = require('chai').expect;
var sinon = require('sinon');

var NEW = { Message: require('..'), bitcore: require('@runonflux/bitcore-lib') };
var OLD = {
  Message: require('bitcore-message-ec2fb0a'),
  bitcore: require(require.resolve('bitcore-lib', {
    paths: [path.dirname(require.resolve('bitcore-message-ec2fb0a'))]
  }))
};
var LIBS = [OLD, NEW];

function seq(label, n) {
  var out = [];
  for (var i = 0; i < n; i++) {
    out.push(crypto.createHash('sha256').update(label + ':' + i).digest());
  }
  return out;
}

/**
 * Whether the R point a compact signature names lies on secp256k1: its X is
 * r, or r + n for recovery ids 2 and 3, below the field prime, and OpenSSL
 * accepts it as a compressed key.
 */
function compactROnCurve(base64) {
  var buf = Buffer.from(base64, 'base64');
  if (buf.length !== 65) {
    return true;
  }
  if (buf[0] < 27 || buf[0] > 34) {
    return true;
  }
  var i = (buf[0] - 27) & 3;
  var BN = NEW.bitcore.crypto.BN;
  var x = new BN(buf.slice(1, 33));
  if (i > 1) {
    x = x.add(NEW.bitcore.crypto.Point.getN());
  }
  var p = new BN('fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f', 16);
  if (x.cmp(p) >= 0) {
    return false;
  }
  try {
    crypto.ECDH.convertKey(Buffer.concat([Buffer.from([2 + (i & 1)]), x.toBuffer({ size: 32 })]),
      'secp256k1', undefined, 'hex', 'compressed');
    return true;
  } catch (e) {
    return false;
  }
}

function outcome(fn) {
  try {
    var value = fn();
    return { value: Buffer.isBuffer(value) ? value.toString('hex') : value };
  } catch (e) {
    return { error: String(e && e.message) };
  }
}

function same(label, fn) {
  var o = outcome(function() { return fn(OLD); });
  var n = outcome(function() { return fn(NEW); });
  expect(n, label).to.deep.equal(o);
  return o;
}

var MESSAGES = ['', 'hello, world', 'This is an example of a signed message.', 'ünïcödé ✓ 💡',
  'a'.repeat(252), 'b'.repeat(253), 'c'.repeat(65535), 'd'.repeat(65536)];
var NETWORKS = ['livenet', 'testnet'];

describe('Differential against bitcore-message ec2fb0a', function() {

  this.timeout(600000);

  var sandbox;
  var nonce;

  beforeEach(function() {
    sandbox = sinon.createSandbox();
    var randoms = [];
    LIBS.forEach(function(lib) {
      if (randoms.indexOf(lib.bitcore.crypto.Random) === -1) {
        randoms.push(lib.bitcore.crypto.Random);
      }
    });
    randoms.forEach(function(Random) {
      sandbox.stub(Random, 'getRandomBuffer').callsFake(function(size) {
        return nonce.slice(0, size);
      });
    });
  });

  afterEach(function() {
    sandbox.restore();
  });

  it('computes magic hashes alike', function() {
    MESSAGES.forEach(function(text, i) {
      same('magic hash ' + i, function(lib) {
        var message = new lib.Message(text);
        return {
          hash: message.magicHash().toString('hex'),
          json: message.toJSON(),
          back: lib.Message.fromJSON(message.toJSON()).toString(),
          object: message.toObject(),
          inspect: message.inspect()
        };
      });
    });
  });

  it('signs alike and verifies each other\'s signatures', function() {
    var keys = seq('message-key', 12).map(function(b) { return b.toString('hex'); });
    var nonces = seq('message-nonce', 3);
    keys.forEach(function(keyHex, k) {
      NETWORKS.forEach(function(network) {
        [true, false].forEach(function(compressed) {
          MESSAGES.forEach(function(text, m) {
            nonce = nonces[(k + m) % nonces.length];
            var label = 'key ' + k + ' ' + network + ' ' + compressed + ' message ' + m;
            var sigs = {};
            var o = same(label, function(lib) {
              var key = new lib.bitcore.PrivateKey({
                bn: new lib.bitcore.crypto.BN(keyHex, 16), network: network, compressed: compressed
              });
              var sig = lib.Message(text).sign(key);
              sigs[lib === OLD ? 'old' : 'new'] = sig;
              var message = new lib.Message(text);
              var verified = message.verify(key.toAddress().toString(), sig);
              return { sig: sig, verified: verified, error: message.error, address: key.toAddress().toString() };
            });
            expect(o.value.verified, label).to.equal(true);
            same(label + ' cross', function(lib) {
              var key = new lib.bitcore.PrivateKey({
                bn: new lib.bitcore.crypto.BN(keyHex, 16), network: network, compressed: compressed
              });
              var message = new lib.Message(text);
              var other = lib === OLD ? sigs.new : sigs.old;
              return { verified: message.verify(key.toAddress(), other), error: message.error };
            });
          });
        });
      });
    });
  });

  it('rejects wrong addresses, messages and malformed signatures alike', function() {
    nonce = seq('reject-nonce', 1)[0];
    var keyHex = seq('reject-key', 1)[0].toString('hex');
    var otherHex = seq('reject-other', 1)[0].toString('hex');
    var base = OLD.Message('hello, world').sign(new OLD.bitcore.PrivateKey(keyHex));
    var raw = Buffer.from(base, 'base64');
    var sigs = [base, 'not base64 ***', '', Buffer.alloc(65).toString('base64'), raw.slice(0, 64).toString('base64')];
    for (var header = 27; header < 35; header++) {
      var copy = Buffer.from(raw);
      copy[0] = header;
      sigs.push(copy.toString('base64'));
    }
    [1, 2, 31, 32, 33, 40, 64].forEach(function(index) {
      var copy = Buffer.from(raw);
      copy[index] ^= 0x01;
      sigs.push(copy.toString('base64'));
    });
    seq('reject-r', 40).forEach(function(r, i) {
      var copy = Buffer.from(raw);
      r.copy(copy, 1);
      copy[0] = 27 + 4 + (i % 4);
      sigs.push(copy.toString('base64'));
    });
    var offCurve = 0;
    sigs.forEach(function(sig, i) {
      NETWORKS.forEach(function(network) {
        var verify = function(lib) {
          var key = new lib.bitcore.PrivateKey(keyHex, network);
          var other = new lib.bitcore.PrivateKey(otherHex, network);
          return ['hello, world', 'hello, world!'].map(function(text) {
            return [key, other].map(function(k) {
              var message = new lib.Message(text);
              var result = outcome(function() { return message.verify(k.toAddress().toString(), sig); });
              return { result: result, error: message.error };
            });
          });
        };
        if (compactROnCurve(sig)) {
          same('reject ' + i + ' ' + network, verify);
          return;
        }
        offCurve++;
        // bitcore-lib 8f5453f recovers a key from an R off the curve and
        // fails validating that key; the bitcore-lib under test rejects R.
        var o = verify(OLD);
        var n = verify(NEW);
        if (JSON.stringify(o) === JSON.stringify(n)) {
          return;
        }
        [0, 1].forEach(function(t) {
          [0, 1].forEach(function(k) {
            expect(o[t][k].result.error, 'reject ' + i + ' at ec2fb0a').to.be.a('string');
            expect(n[t][k].result.error, 'reject ' + i).to.equal('Point does not lie on the curve');
            expect(n[t][k].error, 'reject ' + i).to.equal(o[t][k].error);
          });
        });
      });
    });
    expect(offCurve).to.be.above(0);
  });

  it('checks arguments alike', function() {
    var keyHex = seq('args-key', 1)[0].toString('hex');
    same('arguments', function(lib) {
      var key = new lib.bitcore.PrivateKey(keyHex);
      return [
        outcome(function() { return new lib.Message(5); }),
        outcome(function() { return lib.Message('x').sign('key'); }),
        outcome(function() { return lib.Message('x').verify(); }),
        outcome(function() { return lib.Message('x').verify(key.toAddress().toString(), 5); }),
        outcome(function() { return lib.Message('x').verify('notanaddress', 'H' + 'A'.repeat(87)); }),
        outcome(function() { return lib.Message('x')._verify('pub', 'sig'); }),
        outcome(function() { return lib.Message.fromJSON('{"message":"m"}').toString(); }),
        outcome(function() { return lib.Message.fromJSON({ message: 'm' }).toString(); })
      ];
    });
  });
});
