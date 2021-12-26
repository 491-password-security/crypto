var crypto = require('../crypto.js');

const MOD = crypto.constants.MOD;
const GEN = crypto.constants.GEN;
const Number = crypto.Number;

const ONE = new Number('1');

const MOD_1 = MOD.subtract(ONE);

function OT(choice, m_0, m_1) {
    let receiver = new crypto.ObliviousTransferReceiver(choice, null, null);
    let sender = new crypto.ObliviousTransferSender(m_0, m_1, null, null);

    let C = sender.C;

    receiver.generateKeys(C);

    let receiverKey = receiver.keys[receiver.choice];

    sender.generateKeys(receiverKey);

    var [e_0, e_1] = sender.encryptMessages();

    let result = receiver.readMessage([e_0, e_1]);

    return result; // returns Number
}

function F(k, bits) {
    let exp = new Number('1');
    for (var i = 0; i < 256; i++) {
        if (bits[i] == '1') {
            exp = exp.multiply(k[i]).mod(MOD);
        }
    }
    return GEN.modPow(exp, MOD);
}

function OPRF(k,bits) {
    let a = crypto.util.generatePRFKey(256);

    let client_prod = new Number('1');
    let server_prod = new Number('1');
    for (var i = 0; i < 256; i++) {
        let m_0 = a[i];
        let m_1 = a[i].multiply(k[i]).mod(MOD);
        
        server_prod = server_prod.multiply(m_0).mod(MOD);

        let client_reveal = OT(parseInt(bits[i]), m_0, m_1);

        client_prod = client_prod.multiply(client_reveal).mod(MOD);
    }

    let server_prod_inv = server_prod.modInverse(MOD);

    let exp = server_prod_inv.multiply(client_prod).mod(MOD);
    return GEN.modPow(exp, MOD);
}

let pwd = 'helloworld';

// random group element
let r = GEN.modPow(crypto.util.getBoundedBigInt(MOD), MOD);
let r_inv = r.modInverse(MOD_1);
let k = GEN.modPow(crypto.util.getBoundedBigInt(MOD), MOD);

let a = crypto.util.groupHash(pwd).modPow(r, MOD);

let b = a.modPow(k, MOD);

let result = crypto.util.hash(pwd + b.modPow(r_inv, MOD).hex);

let trueResult = crypto.util.hash(pwd + crypto.util.groupHash(pwd).modPow(k, MOD).hex);

console.log(result)
console.log(trueResult)