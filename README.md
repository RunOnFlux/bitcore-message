# Flux Message Verification and Signing for Bitcore


bitcore-message-hush adds support for verifying and signing hush messages in [Node.js](http://nodejs.org/) and web browsers.

See [the main bitcore repo](https://github.com/bitpay/bitcore) for more information.

## Getting Started

```sh
git clone https://github.com/runonflux/bitcore-message.git
cd bitcore-message
npm install --save
```

To sign a message:

```javascript
var bitcore = require('bitcore-lib');
var Message = require('bitcore-message');

var privateKey = bitcore.PrivateKey.fromWIF('cPBn5A4ikZvBTQ8D7NnvHZYCAxzDZ5Z2TSGW2LkyPiLxqYaJPBW4');
var signature = Message('hello, world').sign(privateKey);
```

To verify a message:

```javascript
var address = 'n1ZCYg9YXtB5XCZazLxSmPDa8iwJRZHhGx';
var signature = 'H/DIn8uA1scAuKLlCx+/9LnAcJtwQQ0PmcPrJUq90aboLv3fH5fFvY+vmbfOSFEtGarznYli6ShPr9RXwY9UrIY=';
var verified = Message('hello, world').verify(address, signature);
```

## Tests

Requires Node.js 24 or later.

```sh
npm test
```

`npm test` runs every file under `test/` in its own mocha process and checks
each outcome against `test/inherited-failures.json`, the inherited tests that
fail at runonflux/bitcore-message ec2fb0a with bitcore-lib 8f5453f.

## License

Code released under [the MIT license](https://github.com/bitpay/bitcore/blob/master/LICENSE).

Copyright 2013-2015 BitPay, Inc. Bitcore is a trademark maintained by BitPay, Inc.

