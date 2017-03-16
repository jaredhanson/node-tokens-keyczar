var keyczar = require('keyczarjs');
keyczar.util = require('keyczarjs/keyczar_util');

// Google: keycar tokens
// https://dzone.com/articles/easy-encryption-java-and-pytho

module.exports = function(options, keying) {
  if (typeof options == 'function') {
    keying = options;
    options = undefined;
  }
  options = options || {};
  
  return function keyczar_seal(claims, options, cb) {
    console.log('KEYCZAR SEAL');
    console.log(claims);
    
    var query  = {
      recipients: options.audience,
      usage: 'encrypt',
      algorithms: [ 'aes256-cbc' ],
      length: 16
    }
    
    keying(query, function(err, keys) {
      console.log('GOT KEYS');
      console.log(err);
      console.log(keys);
      
      var keyset = keyczar.create(keyczar.TYPE_AES);
      var keysetSerialized = keyset.toJson();
      console.log(keyset)
      console.log(keysetSerialized);
      
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
      
      console.log('---');
      console.log(keysetSerialized);
    
      var plaintext = 'hello message';
      var plaintext = JSON.stringify(claims);
    
      keyset = keyczar.fromJson(keysetSerialized);
      var encrypted = keyset.encrypt(plaintext);
    
      console.log('ENCRYPTED');
      console.log(encrypted)
    
      var decrypted = keyset.decrypt(encrypted);
      console.log('plaintext:', plaintext);
      
      return cb(null, encrypted);
    });
    
  };
};
