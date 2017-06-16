var keyczar = require('keyczarjs');
var keyczar_util = require('keyczarjs/keyczar_util');
var aes = require('./type/aes');

// Google: keycar tokens
// https://dzone.com/articles/easy-encryption-java-and-pytho

module.exports = function(options, keying) {
  if (typeof options == 'function') {
    keying = options;
    options = undefined;
  }
  options = options || {};
  
  return function keyczar_seal(claims, options, cb) {
    if (typeof options == 'function') {
      cb = options;
      options = undefined;
    }
    options = options || {};
    
    var audience = options.audience || [];
    if (audience.length > 1) {
      return cb(new Error('Unable to seal iron tokens for multiple recipients'));
    }
    
    
    function encrypt(encryptionKey, signingKey) {
      // TODO: Other payload formats (messagepack, etc)
      var message = JSON.stringify(claims);
      
      var keyset = aes.toKeyset(encryptionKey.secret, signingKey.secret);
      var encrypted = keyset.encrypt(message);
      return cb(null, encrypted);
    }
    
    var query  = {
      usage: 'encrypt',
      recipient: audience[0],
      algorithms: [ 'aes128-cbc' ]
    }
    
    keying(query, function(err, encryptionKeys) {
      if (err) { return cb(err); }
      
      var key = encryptionKeys[0];
      if (key.usages && key.usages.indexOf('sign') !== -1) {
        // The encryption key also allows usage for signing operations.  Proceed
        // to use the same key for both encryption and signing.
        return encrypt(key, key);
      }
      
      // The encryption key has been obtained, query for the signing key.
      var query  = {
        usage: 'sign',
        recipient: audience[0],
        algorithms: [ 'hmac-sha256' ]
      }
      
      keying(query, function(err, signingKeys) {
        if (err) { return cb(err); }
        return encrypt(key, signingKeys[0]);
      });
    });
  };
};
