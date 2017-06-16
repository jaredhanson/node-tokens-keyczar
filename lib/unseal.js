var keyczar = require('keyczarjs');
keyczar.util = require('keyczarjs/keyczar_util');
var aes = require('./type/aes');

var VERSION_BYTE = '\x00';


module.exports = function(options, keying) {
  if (typeof options == 'function') {
    keying = options;
    options = undefined;
  }
  options = options || {};
  
  
  return function keyczar_unseal(t, cb) {
    var char = t.charAt(0)
    
    
    function decrypt(encryptionKeys, signingKeys) {
      // TODO: Iterate over all keys, in order to support key rotation
      var keyset = aes.toKeyset(encryptionKeys[0].secret, signingKeys[0].secret);
      var decrypted = keyset.decrypt(t);
      
      // TODO: Other payload formats (messagepack, etc)
      var claims = JSON.parse(decrypted);
      
      var tkn = {
        headers: {
        },
        claims: claims
      }
      return cb(null, tkn);
    }
    
    
    var query  = {
      usage: 'decrypt',
      algorithms: [ 'aes128-cbc' ]
    }
    
    keying(query, function(err, keys) {
      if (err) { return cb(err); }
      
      // The decryption keys have been obtained, query for the verification keys.
      var query  = {
        usage: 'verify',
        algorithms: [ 'hmac-sha256' ]
      }
      
      keying(query, function(err, signingKeys) {
        if (err) { return cb(err); }
        return decrypt(keys, signingKeys);
      });
    });
  };
};
