'use strict';

var P2PBuffer = require('./p2pbuffer.js').P2PBuffer;
var scriptToAsm = require('./script.js').scriptToAsm;
var opcodes = require('./script.js').opcodes;

var net = require('net');
var crypto = require('crypto');
var util = require('util');
var bs58 = require('bs58');

function inPlaceReverse(buf, copy) {
  var end = buf.length;
  var i, h = Math.ceil(end/2), ii, tmp;

  var original = buf;
  var buf = new Buffer(buf.length);
  original.copy(buf);

  for ( i=0; i<h; i++ ) {
    ii      = end-i-1;
    tmp     = buf[i];
    buf[i]  = buf[ii];
    buf[ii] = tmp;
  }

  return buf;
}

var P2PSocket = function(magic, p2pkh_byte, divisor) {
  this.constructor.super_.apply(this)

  this._nonce = 1;

  this._magic   = magic;
  this._p2pkh_byte = p2pkh_byte || 0x6f;
  this._divisor = divisor || 100000000;

  var _super_connect = this.connect;

  this.on('data', this.receive);
}

util.inherits(P2PSocket, net.Socket);

P2PSocket.prototype.sendPacket = function(method, payload) {
  this.write(payload.packetHeader(this._magic,method));
  this.write(payload.toBuffer());
}

P2PSocket.prototype.parseVersion = function(payload) {

  var content = {
    protocolversion: payload.readUInt32LE(0)
  };

  var i = 4;

  content.services    = payload.readInt64(i);
  i += 8;

  content.timestamp   = new Date(payload.readInt64(i)*1000);
  i += 8;

  content.addr_recv   = payload.readAddr(i);
  i += 26;

  content.addr_from   = payload.readAddr(i);
  i += 26;

  content.nonce       = payload.readInt64(i);
  i += 8;

  var ua = payload.readVarStr(i);
  content.user_agent   = ua.value;
  i += ua.size;

  content.start_height = payload.readUInt32LE(i);
  i += 4;

  if ( content.protocolversion >= 70001 && i < payload.length ) {
    content.relay = payload.readUInt8(i);
  } else {
    content.relay = undefined;
  }

  return content;
}

P2PSocket.prototype.parseInv = function(payload) {
  var content = {
    inventory: []
  };

  var raw_count = payload.readVarInt(0);
  var size = raw_count.size;
  content.count = raw_count.value;

  var i;
  for ( i=0; i < content.count; i++ ) {
    var offset = size + i * 36;
    content.inventory.push({
      type: payload.readUInt32LE(offset),
      hash: inPlaceReverse(payload.slice(offset + 4, offset + 4 + 32)).toString('hex')
    });
  }

  return content;
}

P2PSocket.prototype.parseBlock = function(payload) {

  var header = payload.slice(0,80);

  var sha256_pass1 = crypto.createHash('sha256').update(header).digest();
  var blockhash = inPlaceReverse(crypto.createHash('sha256').update(sha256_pass1).digest()).toString('hex');

  var content = {
    hash:              blockhash,
    confirmations:     undefined,
    size:              payload.length,
    height:            undefined,
    version:           payload.readUInt32LE(0),
    merkleroot:        inPlaceReverse(payload.slice(36,68)).toString('hex'),
    tx:                [],
    time:              payload.readUInt32LE(68),
    nonce:             payload.readUInt32LE(76),
    bits:              inPlaceReverse(payload.slice(72,76)).toString('hex'),
    difficulty:        undefined,
    chainwork:         undefined,
    previousblockhash: inPlaceReverse(payload.slice(4,36)).toString('hex'),
  };

  var txc = payload.readVarInt(80);

  var i, base = 80+txc.size;

  for ( i=0; i<txc.value; i++ ) {
    var tx = this.parseTx(new P2PBuffer(payload.slice(base)));
    content.tx.push(tx);
    base +=  tx.hex.length / 2;
  }


  /*
   * Get the bip-0034 height if the block version is greater than 1
   * https://github.com/bitcoin/bips/blob/master/bip-0034.mediawiki
   */
  if ( content.version > 1 ) {
    var coinbase = content.tx[0];
    content.height = 0;

    var script = new Buffer(coinbase.vin[0].coinbase,'hex');
    var s = script.readUInt8(0);
    for (i=0; i<s && i<3; i++) {
      content.height += script.readUInt8(i+1) * ( i > 0 ? i*256 : 1);
    }
  }


  return content;
}

P2PSocket.prototype.parseTx = function(payload) {

  var content = {
    version: payload.readUInt32LE(0),
    hex:  null,
    txid: null,
    lock_time: null,
    vin:  [],
    vout: [],
  };

  var i = 4;

  var cin = payload.readVarInt(i);
  i += cin.size;

  var n;
  for ( n=0; n < cin.value; n++ ) {

    var tx = {
      txid: inPlaceReverse(payload.slice(i, i+32),true).toString('hex'),
      vout: payload.readUInt32LE(i+32)
    };

    i += 36;

    var sl = payload.readVarInt(i);
    i += sl.size;

    var scriptSig = payload.slice(i, i+sl.value);
    tx.scriptSig = {
      hex: scriptSig.toString('hex'),
      asm: scriptToAsm(scriptSig),
    }

    i += sl.value;

    tx.sequence = payload.readUInt32LE(i);
    i += 4;

    if ( tx.vout === tx.sequence && tx.txid.match(/^0+$/) ) {
      tx = {
        coinbase: tx.scriptSig.hex,
        sequence: tx.sequence,
      }
    }

    content.vin.push(tx);
  }

  var cout = payload.readVarInt(i);
  i += cout.size;

  for ( n=0; n < cout.value; n++ ) {

    var tx = {
      value: payload.readInt64(i) / this._divisor,
    };

    i += 8;

    var pkl = payload.readVarInt(i);
    i += pkl.size;

    var scriptPubKey = payload.slice(i, i+pkl.value);
    tx.scriptPubKey = {
      hex: scriptPubKey.toString('hex'),
      asm: scriptToAsm(scriptPubKey),
    }

    if ( scriptPubKey.length === 25 && scriptPubKey[0] === opcodes.OP_DUP &&
         scriptPubKey[1] === opcodes.OP_HASH160 && scriptPubKey[2] === 20 &&
         scriptPubKey[23] === opcodes.OP_EQUALVERIFY &&
         scriptPubKey[24] === opcodes.OP_CHECKSIG
     ) {
      tx.scriptPubKey.reqSigs = 1;
      tx.scriptPubKey.type = 'pubkeyhash';

      var hash = scriptPubKey.slice( 3, 23 );

      var addrBuf = new Buffer( hash.length + 1 );
      addrBuf[0] = this._p2pkh_byte;
      hash.copy( addrBuf, 1, 0 );

      var sha256_pass1 = crypto.createHash('sha256').update(addrBuf).digest();
      var sha256 = crypto.createHash('sha256').update(sha256_pass1).digest();

      tx.scriptPubKey.addresses = [
        bs58.encode( Buffer.concat( [addrBuf, sha256.slice(0,4)], addrBuf.length + 4 ) )
      ];
    }

    i += pkl.value;

    tx.n = n;

    content.vout.push(tx);
  }

  content.lock_time =  payload.readUInt32LE(i);

  var raw = payload.slice(0,i+4);

  var sha256_pass1 = crypto.createHash('sha256').update(raw).digest();
  content.txid = inPlaceReverse(crypto.createHash('sha256').update(sha256_pass1).digest()).toString('hex');

  content.hex = raw.toString('hex');

  return content;
}

P2PSocket.prototype.parse = function(method, payload) {
  switch( method ) {
    case 'version':  return this.parseVersion(payload);
    case 'getdata':
    case 'inv':
    case 'notfound': return this.parseInv(payload);
    case 'block':    return this.parseBlock(payload);
    case 'tx':       return this.parseTx(payload);
    default:         return null;
  }
}

P2PSocket.prototype.receive = function(data) {
  var buffer = new Buffer(data);
  var headerSize = 24;

  var message = {
    raw: buffer
  };

  var i = 0;
  message.magic  = buffer.slice(0,this._magic.length);
  i += this._magic.length;

  message.method = buffer.slice(i,i+12).toString('ascii').replace(/\0+$/,'');
  i += 12;

  message.payload_length = buffer.readUInt32LE(i);
  i += 4;

  message.expected_checksum = buffer.slice(i, i+4);
  i+= 4;

  message.payload = new P2PBuffer(buffer.slice(i, i + message.payload_length));

  var sha256_pass1 = crypto.createHash('sha256').update(message.payload.toBuffer()).digest();
  var sha256 = crypto.createHash('sha256').update(sha256_pass1).digest();
  message.checksum = sha256.slice(0, 4);

  message.content = this.parse(message.method, message.payload);

  this.emit('p2p_' + message.method, message.content);

  if ( message.payload_length + headerSize < buffer.length ) {
    this.receive(buffer.slice(message.payload_length + headerSize));

  } else if ( message.payload_length + headerSize > buffer.length ) {
    throw "Incomplete message";

  }
}

/*
 * Expected values of inventory:
 *   [
 *     { "type": 1, "hash": "e65efa60566..." },
 *     ...
 *   ]
 *   or
 *   [
 *     { "type": 1, "hash": < Buffer 1b 82 f9 5f 7d 30 b9  ...>" },
 *     ...
 *   ]
 * When using buffer the value of the buffer must be in little-endian byte order,
 * which is the opposite of if you read the hex string left to right.
 *
 * Types are:
 *   0 = error (ignored)
 *   1 = transaction
 *   2 = block
 *   3 = filtered block
 */
P2PSocket.prototype.getdata = function( inventory ) {
  var l = inventory.length;
  var start = P2PBuffer.getVarIntSize(l);

  var buffer = new P2PBuffer(l * 36 + start );

  buffer.writeVarInt(l);

  var i;
  for ( i=0; i < l; i++ ) {
    buffer.writeUInt32LE( inventory[i].type, start + 36*i );

    var hash = inventory[i].hash instanceof Buffer ? inventory[i].hash : inPlaceReverse(new Buffer(inventory[i].hash,'hex'));
    hash.copy( buffer, start + 36*i + 4 );
  }

  this.sendPacket("getdata", buffer);
}

P2PSocket.prototype.mempool = function() {
  this.sendPacket("mempool", new P2PBuffer(0));
}

P2PSocket.prototype.version = function() {
  var userAgent = "/Ziftr Skinny Peer:0.2/";

  var size = 85 + P2PBuffer.getVarStrSize(userAgent);
  var buffer = new P2PBuffer(size);
  var i = 0;

  this._nonce++;

  buffer.writeUInt32LE(0x60002, i);
  i += 4;

  buffer.writeInt64(0, i);
  i += 8;

  buffer.writeInt64(new Date().getTime(), i);
  i += 8;

  buffer.writeAddr(this.remoteAddress, this.remotePort, i);
  i += 26;

  buffer.writeAddr(this.localAddress,  this.localPort,  i);
  i += 26;

  buffer.writeInt64(this._nonce, i);
  i += 8;

  buffer.writeVarStr(userAgent, i);
  i += P2PBuffer.getVarStrSize(userAgent);

  buffer.writeUInt32LE(0, i);
  i += 4;

  buffer.writeUInt8(1, i);

  this.sendPacket("version", buffer);
}

P2PSocket.prototype.connect = function(port, host, connectListener) {
  var self = this;
  this.constructor.super_.prototype.connect.call(this, port, host, function() {
    self.version();
    if ( connectListener ) {
      connectListener();
    }
  });
};

exports.P2PSocket = P2PSocket;
