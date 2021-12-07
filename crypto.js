global.Buffer = global.Buffer || require('buffer').Buffer

var sjcl = require('./sjcl');
var secrets = require('shamirs-secret-sharing');


function random(bits, returnBits=false) {
    var rand = sjcl.random.randomWords(bits/32);
    return (returnBits) ? rand : sjcl.codec.hex.fromBits(rand);
}

function hash(input) {
    var out = sjcl.hash.sha256.hash(input);
    return sjcl.codec.hex.fromBits(out);
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

function share(secret, t, n) {
    let hex_shares = [];
    let shares = secrets.split(Buffer.from(secret), { shares: n, threshold: t });
    for (let i = 0; i < shares.length; i++) {
        hex_shares.push(shares[i].toString('hex'));
    }
    return hex_shares;
}

function combine(shares, encoding='hex') {
    return secrets.combine(shares).toString(encoding);
}

module.exports = {random, hash, encrypt, decrypt, share, combine};

console.log(share("hello", 2, 3))