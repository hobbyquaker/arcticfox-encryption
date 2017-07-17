require('should');

const ArcticfoxEncryption = require('./index.js');

const afc = new ArcticfoxEncryption();

describe('encode and decode', () => {
    it('should encode and decode', () => {
        const text = 'this is a test!';
        const encoded = afc.encode(Buffer.from(text));
        const decoded = afc.decode(encoded).toString();
        text.should.equal(decoded);
    });
});
