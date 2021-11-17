var sjcl = require('sjcl');
var secrets = require('secrets.js-grempe');
var elgamal = require('elgamal');
const { BigInteger } = require('jsbn');

const BIG_TWO = new BigInteger('2');
const BIG_ONE = new BigInteger('1');

// TODO: reorganize
// TODO: comments
// TODO: pseudorandom function

// TODO: is this ok? (I think it is)
// these are *not* secret values
// MOD = prime
// GEN = generator of multiplicative group Z_p
// GEN ^ (MOD - 1) = 1 mod MOD
const MOD = new BigInteger('104334873255401717971305551311108568981602782554133676271604158174023613565338436519535738349159664075981513545995816898351274759273689547803611869080590323788134546218679576525351375421659491479861062524332418185137628175629882792848502958254366030986728999054034830850220407425928535174607722203029578103539');
const GEN = new BigInteger('15309569078288033140294527228325069587420150399530450735556668091277116408023136181284430449588830517258893721878398739530623279778683647761572205172467420662396761999763043433000129229039419004108765113420973429371572791200022523422170732284615282345655002021445578558188416639692531759416866286539604862128');


function random(bits, returnBits=false) {
    var rand = sjcl.random.randomWords(bits/32);
    return (returnBits) ? rand : sjcl.codec.hex.fromBits(rand);
}

function hash(input, returnBits=false) {
    var out = sjcl.hash.sha256.hash(input);
    return (returnBits) ? out : sjcl.codec.hex.fromBits(out);
}

function extendedHash(input, count) {
    let last_output = input;
    let result = [];
    for (var i = 0; i < count; i++) {
        last_output = hash(sjcl.codec.hex.fromBits(last_output), returnBits=true);
        result = result.concat(last_output);
    }
    return result;
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

module.exports = {random, hash, encrypt, decrypt, share, combine, newShare};

function getBoundedBigInt(max) {
    let bits = max.bitLength();
    do {
        var rand = new BigInteger(random(bits));
    } while (rand.compareTo(max) >= 0);
    return rand;
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

function wordWiseXOR(u, v) {
    var result = [];
    for (var i = 0; i < u.length; i++) {
        try {
            result.push(u[i] ^ v[i]);   
        } catch (error) {
            break;
        }
    }
    return result;
}

class ObliviousTransferReceiver {
    constructor(choice) {
        // TODO: raise exception if choice not one or zero
        this.choice = choice;
        this.keys = [];
        
        // pick random element from additive Z_p
        this.k = getBoundedBigInt(MOD);        
    }

    generateKeys(C) {
        // generate two random keys (as elements from multiplicative Z_p) also using C
        let choiceKey = GEN.modPow(this.k, MOD);
        let negChoiceKey = C.divide(choiceKey).mod(MOD);
        this.keys = [choiceKey, negChoiceKey];
    }

    readMessage(choices) {
        // choose one of the messages
        let ciphertext = choices[this.choice];

        // g^(r_sigma)^k = PK_sigma^(r_sigma)
        let xorKey = extendedHash(ciphertext[0].modPow(this.k, MOD), 4);

        // decrypt the ciphertext
        return wordWiseXOR(ciphertext[1], xorKey);
    }
}

class OblivousTransferSender {
    constructor(m_0, m_1) {
        this.m_0 = m_0;
        this.m_1 = m_1;

        // initiate random constants
        this.C = getBoundedBigInt(MOD);
        this.r_0 = getBoundedBigInt(MOD);
        this.r_1 = getBoundedBigInt(MOD);
    }

    generateKeys(receiverKey) {
        // generate keys for each message based on receiver's key and the hidden random values
        this.key_0 = receiverKey.modPow(this.r_0, MOD);
        this.key_1 = C.divide(this.key_0).modPow(this.r_1, MOD);
        this.keys = [this.key_0, this.key_1];
    }

    encryptMessages() {
        // encrypt (hash + xor) each message using one of the keys
        let e_0 = [GEN.modPow(this.r_0, MOD), wordWiseXOR(extendedHash(this.key_0, 4), this.m_0)];
        let e_1 = [GEN.modPow(this.r_1, MOD), wordWiseXOR(extendedHash(this.key_1, 4), this.m_1)];
        return [e_0, e_1];
    }
}

// let m_0 = getBoundedBigInt(MOD);
// let m_1 = getBoundedBigInt(MOD);

// console.log(m_0);
// console.log(m_1);

// let receiver = new ObliviousTransferReceiver(0);
// let sender = new OblivousTransferSender(m_0, m_1);

// let C = sender.C;

// receiver.generateKeys(C);

// let receiverKey = receiver.keys[receiver.choice];

// sender.generateKeys(receiverKey);

// [e_0, e_1] = sender.encryptMessages();

// let result = receiver.readMessage([e_0, e_1]);

// console.log(result);

