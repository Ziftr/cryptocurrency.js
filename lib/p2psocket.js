'use strict';

var P2PBuffer = require('./p2pbuffer.js').P2PBuffer;
var net = require('net');
var crypto = require('crypto');
var util = require('util');

var P2PSocket = function(magic) {
  this.constructor.super_.apply(this)

  this.nonce = 1;

  this.magic = magic;
  
  var _super_connect = this.connect;
  
  this.on('data', this.receive);
}

util.inherits(P2PSocket, net.Socket);

P2PSocket.prototype.sendPacket = function(method, payload) {
  this.write(payload.packetHeader(this.magic,method));
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

  content.addr_recv   = payload.readAddr(true, i);
  i += 26;
  
  content.addr_from   = payload.readAddr(true, i);
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
      hash: payload.slice(offset + 4, offset + 4 + 32)
    });
  }

  return content;
}

P2PSocket.prototype.parseTx = function(payload) {
  var content = {
    version: payload.readUInt32LE(0),
    vin:  [],
    vout: [],
  };
  
  var i = 4;
  
  var cin = payload.readVarInt(i);
  i += cin.size;
  
  var n;
  for ( n=0; n < cin.value; n++ ) {
  
    var tx = {
      previous_output: {
        txid: payload.slice(i, i+32),
        vout: payload.readUInt32LE(i+32),
      },
    };
    
    i += 36;
    
    var sl = payload.readVarInt(i);
    i += sl.size;
    
    tx.scriptSig = payload.slice(i, i+sl.value);
    i += sl.value;
    
    tx.sequence = payload.readUInt32LE(i);
    i += 4;
    
    content.vin.push(tx);      
  }

  var cout = payload.readVarInt(i);
  i += cout.size;
  
  for ( n=0; n < cout.value; n++ ) {
  
    var tx = {
      value: payload.readInt64(i),
    };
    
    i += 8;
    
    var pkl = payload.readVarInt(i);
    i += pkl.size;
    
    tx.scriptPubKey = payload.slice(i, i+pkl.value);
    i += pkl.value;
    
    tx.n = n;
    
    content.vout.push(tx);      
  }

  return content;
}

P2PSocket.prototype.parse = function(method, payload) {
  switch( method ) {
    case 'version': return this.parseVersion(payload);
    case 'inv':     return this.parseInv(payload);
    case 'tx':      return this.parseTx(payload);
    default:        return null;
  }
}

P2PSocket.prototype.receive = function(data) {
  var buffer = new Buffer(data);

  var message = {
    raw: buffer
  };

  var i = 0;
  message.magic  = buffer.slice(0,this.magic.length);
  i += this.magic.length;

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
  console.log(message);
  this.emit('p2p_' + message.method, message.content);
  return message;
}

P2PSocket.prototype.version = function() {
  var userAgent = "/Ziftr Skinny Peer:0.1/";

  var size = 85 + P2PBuffer.getVarStrSize(userAgent);
  var buffer = new P2PBuffer(size);
  var i = 0;

  this.nonce++;

  buffer.writeUInt32LE(0x60002, i);
  i += 4;

  buffer.writeInt64(0, i);
  i += 8;

  buffer.writeInt64(new Date().getTime(), i);
  i += 8;

  buffer.writeAddr(true, this.remoteAddress, this.remotePort, i);
  i += 26;
  
  buffer.writeAddr(true, this.localAddress,  this.localPort,  i);
  i += 26;

  buffer.writeInt64(this.nonce, i);
  i += 8;

  buffer.writeVarStr(userAgent, i);
  i += P2PBuffer.getVarStrSize(userAgent);

  buffer.writeUInt32LE(0, i);
  i += 4;

  buffer.writeUInt8(1, i);

  this.sendPacket("version", buffer);
}

P2PSocket.prototype.getdata = function( inventory ) {
  var l = inventory.length;
  var start = P2PBuffer.getVarIntSize(l);

  var buffer = new P2PBuffer(l * 36 + start );
  
  buffer.writeVarInt(l);
      
  var i;
  for ( i=0; i < l; i++ ) {
    buffer.writeUInt32LE( inventory[i].type, start + 36*i );
    inventory[i].hash.copy( buffer, start + 36*i + 4 );
  }
  
  this.sendPacket("getdata", buffer);
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
