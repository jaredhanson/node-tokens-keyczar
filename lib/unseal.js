var keyczar = require('keyczarjs');
keyczar.util = require('keyczarjs/keyczar_util');

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
      
      
      var meta = {
          name: '',
          purpose: keyczar.PURPOSE_DECRYPT_ENCRYPT,
          type: keyczar.TYPE_AES,
          encrypted: false,
          versions: [{
            exportable: false,
            status: 'PRIMARY',
            versionNumber: 1
          }]
        };
      var keyString = {
        mode: 'CBC',
        aesKeyString: keyczar.util.encodeBase64Url(keys[0].secret),
        size: 128,
        hmacKey: {
          hmacKeyString: keyczar.util.encodeBase64Url(keys[0].secret + keys[0].secret),
          size: 256
        }
      }
      
      var keysetSerialized = {
        meta: JSON.stringify(meta),
        '1': JSON.stringify(keyString)
      }
      keysetSerialized = JSON.stringify(keysetSerialized);
      
      var keyset = keyczar.fromJson(keysetSerialized);
      
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
