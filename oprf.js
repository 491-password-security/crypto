const { BigInteger } = require('jsbn');
var crypto = require('./crypto.js');
var ot = require('./ot.js');

const MOD = crypto.constants.MOD;
const GEN = crypto.constants.GEN;
const Number = crypto.Number;

const ONE = new Number('1');
const MOD_1 = MOD.subtract(ONE);


// class OPRFInputHolder {
//     constructor(input, sendCallback, receiveCallback, address) {
//         this.sendCallback = sendCallback;
//         this.receiveCallback = receiveCallback;
//         this.address = address;
//         this.input = input;
//     }

//     start() {
//         let x = crypto.util.hex2bin(crypto.util.hash(this.input));
//         for (var choice in x) {
//             console.log(choice);
//         }
//     }
// }

// class OPRFKeyHolder {

// }

function OT(choice, m_0, m_1) {
    let receiver = new ot.ObliviousTransferReceiver(choice, null, null);
    let sender = new ot.ObliviousTransferSender(m_0, m_1, null, null);

    let C = sender.C;

    receiver.generateKeys(C);

    let receiverKey = receiver.keys[receiver.choice];

    sender.generateKeys(receiverKey);

    var [e_0, e_1] = sender.encryptMessages();

    let result = receiver.readMessage([e_0, e_1]);

    return result; // returns Number
}

function generatePRFKey(count) {
    let key = [];
    for (var i = 0; i < count; i++) {
        let pow = crypto.util.getBoundedBigInt(MOD_1);
        key.push(GEN.modPow(pow, MOD));
    }        
    return key;
}

function F(k, bits) {
    let exp = new Number('1');
    for (var i = 0; i < 256; i++) {
        if (bits[i] == '1') {
            exp = exp.multiply(k[i]).mod(MOD);
        }
    }
    console.log('f exp: ', exp.bigInt.toString())
    return GEN.modPow(exp, MOD);
}

function OPRF(k,bits) {
    let a = generatePRFKey(256);

    let client_prod = new Number('1');
    let server_prod = new Number('1');
    for (var i = 0; i < 256; i++) {
        let m_0 = a[i];
        let m_1 = a[i].multiply(k[i]).mod(MOD);
        
        server_prod = server_prod.multiply(a[i]).mod(MOD);

        let client_reveal = OT(parseInt(bits[i]), m_0, m_1);

        client_prod = client_prod.multiply(client_reveal).mod(MOD);
    }

    server_prod = server_prod.modInverse(MOD);

    let exp = server_prod.multiply(client_prod).mod(MOD);
    console.log('oprf exp: ', exp.bigInt.toString())
    return GEN.modPow(exp, MOD);
}

let pwd = 'helloworld';
let x = new Number(crypto.util.hash(pwd), 16);
let k = generatePRFKey(256);
let bits = crypto.codec.hex2Bin(x.hex);

console.log(F(k, bits).hex);
console.log(OPRF(k, bits).hex);