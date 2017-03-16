var keyczar = require('keyczarjs');
keyczar.util = require('keyczarjs/keyczar_util');

module.exports = function(options, keying) {
  
  return function keyczar_unseal(t, cb) {
    console.log('UNSEAL KEYCZAR!');
    console.log(t);
    
    
    var query  = {
      recipients: options.audience,
      usage: 'decrypt',
      algorithms: [ 'aes256-cbc' ],
      length: 16
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
      
      console.log('DECRYPTED!');
      console.log(decrypted)
      
      var claims = JSON.parse(decrypted);
      
      var tok = {
        issuer: query.sender,
        headers: {
          issuer: claims.iss
        },
        claims: claims
      }
    
      return cb(null, tok);
      
    });
  };
};
