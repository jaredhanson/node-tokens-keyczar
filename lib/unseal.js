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
    
    
    var query  = {
      usage: 'decrypt',
      algorithms: [ 'aes256-cbc' ]
    }
    
    keying(query, function(err, keys) {
      console.log('GOT KEYS');
      console.log(err);
      console.log(keys);
      
      if (err) { return cb(err); }
      
      
      var keyset = aes.toKeyset(keys[0].secret);
      
      var decrypted = keyset.decrypt(t);
      
      var claims = JSON.parse(decrypted);
      
      var tok = {
        headers: {
        },
        claims: claims
      }
    
      return cb(null, tok);
      
    });
  };
};
