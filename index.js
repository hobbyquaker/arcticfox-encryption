// https://github.com/dotnet/coreclr/blob/master/src/inc/random.h
// http://referencesource.microsoft.com/#mscorlib/system/random.cs

const INT32MIN = -0x80000000;
const INT32MAX = 0x7FFFFFFF;

const MSEED = 161803398;
const MBIG = INT32MAX;

class DotNetRandom {
    constructor(seed) {
        this.SeedArray = new Array(55).fill(0);

        let ii;
        let mj;
        let mk;

        const substraction = (seed === INT32MIN) ? INT32MAX : Math.abs(seed);
        mj = MSEED - substraction;

        this.SeedArray[55] = mj;

        mk = 1;
        for (let i = 1; i < 55; i++) {  // Apparently the range [1..55] is special (Knuth) and so we're wasting the 0'th position.
            ii = (21 * i) % 55;
            this.SeedArray[ii] = mk;
            mk = mj - mk;
            if (mk < 0) {
                mk += MBIG;
            }
            mj = this.SeedArray[ii];
        }

        for (let k = 1; k < 5; k++) {
            for (let i = 1; i < 56; i++) {
                /* eslint-disable no-mixed-operators */
                this.SeedArray[i] = (this.SeedArray[i] - this.SeedArray[1 + (i + 30) % 55]) & 0xFFFFFFFF;
                if (this.SeedArray[i] < 0) {
                    this.SeedArray[i] += MBIG;
                }
            }
        }
        this.inext = 0;
        this.inextp = 21;
    }

    internalSample() {
        let retVal;
        let locINext = this.inext;
        let locINextp = this.inextp;

        if (++locINext >= 56) {
            locINext = 1;
        }
        if (++locINextp >= 56) {
            locINextp = 1;
        }

        retVal = this.SeedArray[locINext] - this.SeedArray[locINextp];

        if (retVal === MBIG) {
            retVal--;
        }
        if (retVal < 0) {
            retVal += MBIG;
        }

        this.SeedArray[locINext] = retVal;

        this.inext = locINext;
        this.inextp = locINextp;

        return retVal;
    }

    nextBytes(buf) {
        for (let i = 0; i < buf.length; i++) {
            buf[i] = this.internalSample() % 256;
        }
    }

}

// https://github.com/TBXin/NFirmwareEditor/blob/master/src/NCore/ArcticFoxEncryption.cs
class ArcticfoxEncryption {
    constructor(keyKey = 0x17, tableLength = 9) {
        this.keyKey = keyKey;
        this.tableLength = tableLength;
    }

    decode(buf) {
        if (!buf || buf.length <= 4) {
            throw new Error();
        }

        const keyBytes = Buffer.alloc(4);
        buf.copy(keyBytes, 0, 0, 4);

        const initialKey = this.readKey(keyBytes);
        const table = this.createTable(initialKey);

        const result = Buffer.alloc(buf.length - keyBytes.length);

        for (let i = 0; i < result.length; i++) {
            const outerIndex = i + keyBytes.length;
            result[i] = buf[outerIndex] ^ table[i % table.length];
        }

        return result;
    }

    encode(buf, key) {
        const initialKey = key || this.createKey();
        const table = this.createTable(initialKey.readInt32LE());
        const keyBytes = this.writeKey(initialKey);
        const result = Buffer.alloc(keyBytes.length + buf.length);
        keyBytes.copy(result, 0, 0, keyBytes.length);
        for (let i = keyBytes.length; i < result.length; i++) {
            const outerIndex = i - keyBytes.length;
            result[i] = buf[outerIndex] ^ table[outerIndex % table.length];
        }

        return result;
    }

    readKey(keyBytes) {
        const decryptedKeyBytes = Buffer.alloc(keyBytes.length);
        for (let i = 0; i < decryptedKeyBytes.length; i++) {
            decryptedKeyBytes[i] = keyBytes[i] ^ this.keyKey;
        }
        return decryptedKeyBytes.readInt32LE();
    }

    writeKey(key) {
        const result = Buffer.alloc(key.length);
        for (let i = 0; i < result.length; i++) {
            result[i] = key[i] ^ this.keyKey;
        }
        return result;
    }

    createTable(seed) {
        const result = Buffer.alloc(this.tableLength);
        (new DotNetRandom(seed)).nextBytes(result);
        return result;
    }

    createKey() {
        const buf = Buffer.alloc(4);
        buf.writeInt32LE((new Date()).getTime() & 0xFFFFFFFF);
        return buf;
    }

}

module.exports = ArcticfoxEncryption;
