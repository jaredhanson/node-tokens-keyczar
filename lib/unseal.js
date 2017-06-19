var keyczar = require('keyczarjs');
var aes = require('./type/aes');
var ALGORITHM_OPTIONS = require('./constants').ALGORITHM_OPTIONS;

var VERSION_BYTE = '\x00';


module.exports = function(options, keying) {
  if (typeof options == 'function') {
    keying = options;
    options = undefined;
  }
  options = options || {};
  
  
  return function keyczar_unseal(sealed, cb) {
    var char = sealed.charAt(0)
    
    
    function decrypt(encryptionKeys, signingKeys) {
      var opts = ALGORITHM_OPTIONS[encryptionKeys[0].algorithm];
      if (!opts) {
        return cb(new Error('Unsupported algorithm: ' + encryptionKeys[0].algorithm));
      }
      
      // TODO: Iterate over all keys, in order to support key rotation
      var keyset = aes.toKeyset(encryptionKeys[0].secret, signingKeys[0].secret, opts);
      var decrypted = keyset.decrypt(sealed);
      
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
