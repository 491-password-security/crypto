var crypto = require('./crypto.js');
const { BigInteger } = require('jsbn');

let Number = crypto.Number;

const MOD = crypto.constants.MOD;
const GEN = crypto.constants.GEN;

module.exports.ObliviousTransferReceiver = class ObliviousTransferReceiver {
    constructor(choice, sendCallback, receiveCallback) {
        if (choice != 0 && choice != 1) {
            throw new Error('Choice neither 1 nor 0. Enter a single integer (0 or 1) as the choice.');
        }
        this.sendCallback = sendCallback;
        this.receiveCallback = receiveCallback;
        this.choice = choice;
        this.keys = [];
        
        // pick random element from additive Z_p
        this.k = crypto.util.getBoundedBigInt(MOD);        
    }

    start(address) {
        // get the random constant C from the sender
        let C = new Number(this.receiveCallback(), 16);

        // generate two keys and send the valid key to the sender
        this.generateKeys(C);
        this.sendCallback(address, this.keys[this.choice].toString(16));

        // receive the two encryptions from the sender
        let choices = this.receiveCallback();

        // decrypt the chosen message
        return this.readMessage(choices);
    }

    generateKeys(C) {
        // generate two random keys (as elements from multiplicative Z_p) also using C
        let choiceKey = GEN.modPow(this.k, MOD);
        let negChoiceKey = choiceKey.modInverse(MOD).multiply(C).mod(MOD);
        this.keys = [choiceKey, negChoiceKey];
    }

    readMessage(choices) {
        // choose one of the messages
        let pair = choices[this.choice];
        let hint = pair[0];
        let ciphertext = pair[1];

        // g^(r_sigma)^k = PK_sigma^(r_sigma)
        let xorKey = crypto.util.extendedHash(hint.modPow(this.k, MOD), 4);

        // decrypt the ciphertext
        return crypto.util.xor(xorKey, ciphertext);
    }
}

module.exports.ObliviousTransferSender = class ObliviousTransferSender {
    constructor(m_0, m_1, sendCallback, receiveCallback) {
        this.m_0 = m_0;
        this.m_1 = m_1;
        this.sendCallback = sendCallback;
        this.receiveCallback = receiveCallback;

        // initiate random constants
        this.log_C = crypto.util.getBoundedBigInt(MOD);
        this.C = GEN.modPow(this.log_C, MOD);
        this.r_0 = crypto.util.getBoundedBigInt(MOD);
        this.r_1 = crypto.util.getBoundedBigInt(MOD);
    }

    start(address) {
        // send the constant value C to the receiver
        this.sendCallback(address, this.C.hex);

        // receive one key from receiver
        let receiverKey = new Number(this.receiveCallback(address), 16);

        // generate two keys based on the received key and the hidden random values
        this.generateKeys(receiverKey);

        // send the encrypted messages to the receiver
        let messages = this.encryptMessages();
        this.sendCallback(address, messages);
    }

    generateKeys(receiverKey) {
        // generate keys for each message based on receiver's key and the hidden random values
        this.key_0 = receiverKey;
        this.key_1 = this.key_0.modInverse(MOD).multiply(this.C).mod(MOD);
        this.key_0 = this.key_0.modPow(this.r_0, MOD);
        this.key_1 = this.key_1.modPow(this.r_1, MOD);
        this.keys = [this.key_0, this.key_1];
    }

    encryptMessages() {
        // encrypt (hash + xor) each message using one of the keys
        let xorKey_0 = crypto.util.extendedHash(this.key_0, 4);
        let xorKey_1 = crypto.util.extendedHash(this.key_1, 4);

        let ct_0 = crypto.util.xor(xorKey_0, this.m_0);
        let ct_1 = crypto.util.xor(xorKey_1, this.m_1);

        let e_0 = [GEN.modPow(this.r_0, MOD), ct_0];
        let e_1 = [GEN.modPow(this.r_1, MOD), ct_1];
        return [e_0, e_1];
    }
}