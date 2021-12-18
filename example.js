var ot = require('./ot.js');
var crypto = require('./crypto.js');
var sjcl = require('./sjcl');
const { BigInteger } = require('jsbn');

let Number = crypto.Number;
const MOD = crypto.constants.MOD;
const GEN = crypto.constants.GEN;
const MOD_1 = MOD.subtract(new Number('1'));

let m_0 = crypto.util.getBoundedBigInt(MOD);
let m_1 = crypto.util.getBoundedBigInt(MOD);

console.log(m_0.hex);
console.log(m_1.hex);

let receiver = new ot.ObliviousTransferReceiver(1, null, null);
let sender = new ot.ObliviousTransferSender(m_0, m_1, null, null);

let C = sender.C;

receiver.generateKeys(C);

let receiverKey = receiver.keys[receiver.choice];

sender.generateKeys(receiverKey);

var [e_0, e_1] = sender.encryptMessages();

let result = receiver.readMessage([e_0, e_1]);

console.log(result.hex)
