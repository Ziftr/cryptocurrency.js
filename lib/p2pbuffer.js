'use strict';

var bignum = require('bignum');
var crypto = require('crypto');
var util = require('util');
var _ = require('lodash');

var P2PBuffer = function() {
  this.constructor.super_.apply(this, arguments)

};

util.inherits(P2PBuffer, Buffer);

P2PBuffer.prototype.writeInt64 = function(value, offset) {
  offset  = offset || 0;

  var x = bignum(value);
  x.toBuffer({endian : 'little', size: 8}).copy(offset, 0, 8);
}

P2PBuffer.prototype.readInt64 = function(offset) {
  offset  = offset || 0;
  var x = bignum.fromBuffer(this.slice(offset, offset+8),{endian : 'little', size: 8});
  return x.toNumber();
}

P2PBuffer.prototype.writeAddr = function(isVersion, addr, port, offset) {
  offset  = offset || 0;

  var buffer = new Buffer(26);
  buffer.fill(0);
  buffer.copy(this, offset, 0, buffer.length);

  return 26;
}

P2PBuffer.prototype.readAddr = function(isVersion, offset) {
  offset  = offset || 0;
  
  var i = isVersion ? offset : offset + 4;
  
  var addr = {
    services:  this.readInt64(i),
    port:      this.readUInt16BE(i + 8 + 16)
  };

  var ip = this.slice(i + 8, i + 8 + 16);
  
  addr.ipv4 = util.format("%d.%d.%d.%d", ip[12], ip[13], ip[14], ip[15]);

  return addr;
}

P2PBuffer.prototype.writeVarInt = function(value, offset) {
  offset  = offset || 0;

  if ( value < 0xfd ) {
    this.writeUInt8(value, offset);
    return 1;

  } else {
    this.writeUInt8(0xfd, offset);
    this.writeUInt16LE(0xfd, offset+1);
    return 3;
  }
}

P2PBuffer.prototype.readVarInt = function(offset) {
  offset  = offset || 0;

  var b0  = this[offset];

  if ( b0 < 0xfd ) {
    return { value: b0, size: 1 };

  } else if ( b0 == 0xfd ) {
    return { value: this.readUInt16LE(offset+1), size: 3 };

  } else {
    return { value: 'unknown' };
  }
}

P2PBuffer.prototype.writeVarStr = function(str, offset) {
  offset  = offset || 0;

  var l = this.writeVarInt(str.length, offset);
  this.write(str, offset + l);

  return l + str.length;
}

P2PBuffer.prototype.readVarStr = function(offset) {
  offset  = offset || 0;

  var l = this.readVarInt(offset);

  return {
    value: this.toString('ascii', offset + l.size, offset + l.size + l.value).replace(/\0+$/,''),
    size:  l.size + l.value
  };
}

P2PBuffer.prototype.packetHeader = function(magic, method) {
  var buffer = this.toBuffer();

  var packet = new Buffer(24);
  packet.fill(0);
  new Buffer(magic).copy(packet);
  packet.write(method,4)
  packet.writeUInt32LE(this.length, 16);

  var sha256_pass1 = crypto.createHash('sha256').update(buffer).digest();
  var sha256 = crypto.createHash('sha256').update(sha256_pass1).digest();
  sha256.copy(packet, 20, 0, 4);

  return packet;
}

P2PBuffer.prototype.toBuffer = function() {
  return this.slice(0, this.length);
}

P2PBuffer.getVarStrSize = function(value) {
  return P2PBuffer.getVarIntSize(value.length) + value.length;
}

P2PBuffer.getVarIntSize = function(value) {
  if ( value <= 0xfd ) { return 1; }
  else { return 3; }
}

P2PBuffer.hashToHex = function( buffer ) {
  var j = buffer.length, hash = "";
  while ( j-- ) {
    hash += buffer[j].toString(16);
  }
  return hash;
}

exports.P2PBuffer = P2PBuffer;
