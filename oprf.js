const { BigInteger } = require('jsbn');
var crypto = require('./crypto.js');
var ot = require('./ot.js');

const MOD = crypto.constants.MOD;
const GEN = crypto.constants.GEN;

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

function F(k, x) {
    let exp = new BigInteger('1');
    for (var i = 0; i < 256; i++) {
        if (x[i] == '1') {
            exp = exp.multiply(k[i]);
        }
    }
    return GEN.modPow(exp, MOD);
}

function OT(choice, m_0, m_1) {
    let receiver = new ot.ObliviousTransferReceiver(0, null, null);
    let sender = new ot.ObliviousTransferSender(m_0, m_1, null, null);

    let C = sender.C;

    receiver.generateKeys(C);

    let receiverKey = receiver.keys[receiver.choice];

    sender.generateKeys(receiverKey);

    var [e_0, e_1] = sender.encryptMessages();

    let result = receiver.readMessage([e_0, e_1]);

    return result;
}

function OPRF(k,x) {
    let a = [];
    for (var i = 0; i < 256; i++) {
        a.push(crypto.util.getBoundedBigInt(MOD));
    }

    let client_prod = new BigInteger('1');
    let server_prod = new BigInteger('1');
    for (var i = 0; i < 256; i++) {
        let m_0 = a[i];
        let m_1 = a[i].multiply(k[i]).mod(MOD.subtract(1));

        server_prod = server_prod.multiply(a[i]).mod(MOD.subtract(1));

        let choice = Math.random(2);
        let client_reveal = OT(choice, m_0, m_1);

        // convert word array to big integer

        client_prod = client_prod.multiply(client_reveal).mod(MOD.subtract(1));
    }

    let exp = server_prod.multiply(client_prod).mod(MOD.subtract(1));
    return GEN.exp(exp).mod(MOD);
}

let pwd = 'helloworld';
let x = crypto.util.hex2bin(crypto.util.hash(pwd));
let k = [];
for (var i = 0; i < 256; i++) {
    k.push(crypto.util.getBoundedBigInt(MOD));
}

console.log(F(k, x).toString());
console.log(OPRF(k, x).toString());