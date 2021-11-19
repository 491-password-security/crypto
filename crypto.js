var sjcl = require('./sjcl');
var secrets = require('secrets.js-grempe');
var elgamal = require('elgamal');
const { BigInteger } = require('jsbn');

class Number {
    constructor(str="1", radix=10) {
        this.bigInt = new BigInteger(str, radix);
    }

    get hex() {
        return this.bigInt.toString(16);
    }
    set hex(val) {
        this.bigInt = new BigInteger(val, 16);
    }

    get bytes() {
        return bigInt2Bytes(this.bigInt);
    }
    set bytes(val) {
        this.bigInt = new BigInteger(bytes2Hex(val), 16);
    }

    get decimal() {
        return this.bigInt.toString(10);
    }

    divide(other) {
        return new Number(this.bigInt.divide(other.bigInt).toString());
    }

    modPow(other, mod) {
        return new Number(this.bigInt.modPow(other.bigInt, mod.bigInt).toString());
    }

    mod(other) {
        return new Number(this.bigInt.mod(other.bigInt).toString());
    }

    modInverse(mod) {
        return new Number(this.bigInt.modInverse(mod.bigInt).toString());
    }

    multiply(other) {
        return new Number(this.bigInt.multiply(other.bigInt).toString());
    }

    compareTo(other){
        return this.bigInt.compareTo(other.bigInt);
    }

    subtract(other) {
        return new Number(this.bigInt.subtract(other.bigInt).toString());
    }
}

const BIG_TWO = new Number('2');
const BIG_ONE = new Number('1');

const MOD = new Number('104334873255401717971305551311108568981602782554133676271604158174023613565338436519535738349159664075981513545995816898351274759273689547803611869080590323788134546218679576525351375421659491479861062524332418185137628175629882792848502958254366030986728999054034830850220407425928535174607722203029578103539');
const GEN = new Number('15309569078288033140294527228325069587420150399530450735556668091277116408023136181284430449588830517258893721878398739530623279778683647761572205172467420662396761999763043433000129229039419004108765113420973429371572791200022523422170732284615282345655002021445578558188416639692531759416866286539604862128');


function random(bits, returnBits=false) {
    var rand = sjcl.random.randomWords(bits/32);
    return (returnBits) ? rand : sjcl.codec.hex.fromBits(rand);
}

function hash(input, returnBits=false) {
    var out = sjcl.hash.sha256.hash(input);
    return (returnBits) ? out : sjcl.codec.hex.fromBits(out);
}

function extendedHash(input, count) {
    let last_output = input.hex;
    let result = [];
    for (var i = 0; i < count; i++) {
        last_output = hash(last_output);
        result.push(last_output);
    }
    return new Number(result.join(''), 16);
}

function encrypt(key, plaintext) {
    key = sjcl.codec.hex.toBits(key);
    plaintext = sjcl.codec.hex.toBits(plaintext);

    var aes = new sjcl.cipher.aes(key);
    var iv = random(128, returnBits=true);
    var ciphertext = sjcl.mode.ccm.encrypt(aes, plaintext ,iv);

    return {
        iv: sjcl.codec.hex.fromBits(iv), 
        ciphertext: sjcl.codec.hex.fromBits(ciphertext)
    };
}

function decrypt(key, iv, ciphertext) {
    key = sjcl.codec.hex.toBits(key);
    iv = sjcl.codec.hex.toBits(iv);
    ciphertext = sjcl.codec.hex.toBits(ciphertext);

    var aes = new sjcl.cipher.aes(key);
    var plaintext = sjcl.mode.ccm.decrypt(aes, ciphertext, iv);

    return sjcl.codec.hex.fromBits(plaintext);
}

// secret will already be a hex string, being the output of a hash function
function share(secret, t, n) {
    return secrets.share(secret, n, t);
}

function combine(shares) {
    return secrets.combine(shares);
}

function newShare(id, shares) {
    return secrets.newShare(id, shares);
}

function getBoundedBigInt(max) {
    let bits = max.bigInt.bitLength();
    let number = new Number(null, null);
    do {
        number.bigInt = new BigInteger(random(bits));
    } while (number.bigInt.compareTo(max) >= 0);
    return number;
}

async function getElGamalKeys(bits) {
    var eg = await elgamal.default.generateAsync(bits);
    return {
        p: eg.p,
        g: eg.g,
        x: eg.x,
        g_x: eg.y,
    };
}

function xor(u, v) {
    let length = Math.min(u.bytes.length, v.bytes.length);
    let resultNum = new Number()
    var result = [];
    for (var i = 0; i < length; i++) {
        result.push(u.bytes[i] ^ v.bytes[i]);   
    }
    resultNum.bytes = result;
    return resultNum;
}   

function hex2Bin(hex){
    var out = "";
    for(var c of hex) {
        switch(c) {
            case '0': out += "0000"; break;
            case '1': out += "0001"; break;
            case '2': out += "0010"; break;
            case '3': out += "0011"; break;
            case '4': out += "0100"; break;
            case '5': out += "0101"; break;
            case '6': out += "0110"; break;
            case '7': out += "0111"; break;
            case '8': out += "1000"; break;
            case '9': out += "1001"; break;
            case 'a': out += "1010"; break;
            case 'b': out += "1011"; break;
            case 'c': out += "1100"; break;
            case 'd': out += "1101"; break;
            case 'e': out += "1110"; break;
            case 'f': out += "1111"; break;
            default: return "";
        }
    }
    return out;
}

function hex2Bytes(hex) {
    if (hex.length % 2 != 0) {
        hex = '0' + hex;
    }
    return sjcl.codec.bytes.fromBits(sjcl.codec.hex.toBits(hex));
}

function bytes2Hex(byteArray) {
    return sjcl.codec.hex.fromBits(sjcl.codec.bytes.toBits(byteArray));
  }

function bytes2BigInt(bytes) {
    return new BigInteger(bytes2Hex(bytes), 16);
}

function bigInt2Bytes(bigInt) {
    return hex2Bytes(bigInt.toString(16));
}

module.exports.constants = {MOD, GEN};
module.exports.ss = {share, combine, newShare};
module.exports.util = {random, hash, extendedHash, getBoundedBigInt, getElGamalKeys, xor};
module.exports.aes = {encrypt, decrypt};
module.exports.codec = {hex2Bytes, hex2Bin, bytes2Hex, bytes2BigInt, bigInt2Bytes}
module.exports.Number = Number;