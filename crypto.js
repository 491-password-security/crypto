var sjcl = require('sjcl');
var secrets = require('secrets.js-grempe');


function hash(input) {
    var out = sjcl.hash.sha256.hash(input);
    return sjcl.codec.hex.fromBits(out);
}

function encrypt(key, plaintext) {
    key = sjcl.codec.hex.toBits(key);
    plaintext = sjcl.codec.utf8String.toBits(plaintext);

    var aes = new sjcl.cipher.aes(key);
    var iv = sjcl.random.randomWords(4);
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

    return sjcl.codec.utf8String.fromBits(plaintext);
}

var keyLength = 192;
var key = sjcl.codec.hex.fromBits(sjcl.random.randomWords(keyLength / 32));

var encResult = encrypt(key, "Hello world!")
console.log(encResult.iv);
console.log(encResult.ciphertext);
console.log(decrypt(key, encResult.iv, encResult.ciphertext));