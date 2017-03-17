var keyczar = require('keyczarjs');
var keyczar_util = require('keyczarjs/keyczar_util');

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
    
    
    var query  = {
      recipients: options.audience,
      usage: 'encrypt',
      algorithms: [ 'aes256-cbc' ],
      length: 16
    }
    
    keying(query, function(err, keys) {
      if (err) { return cb(err); }
      
      var kz_meta = {
        name: '',
        purpose: keyczar.PURPOSE_DECRYPT_ENCRYPT,
        type: keyczar.TYPE_AES,
        encrypted: false,
        versions: [ {
          exportable: false,
          status: 'PRIMARY',
          versionNumber: 1
        } ]
      };
      var kz_key = {
        mode: 'CBC',
        aesKeyString: keyczar_util.encodeBase64Url(keys[0].secret),
        size: 128,
        hmacKey: {
          hmacKeyString: keyczar_util.encodeBase64Url(keys[0].secret + keys[0].secret),
          size: 256
        }
      };
      var sz_keyset = JSON.stringify({
        meta: JSON.stringify(kz_meta),
        '1': JSON.stringify(kz_key)
      });
      
      var message = JSON.stringify(claims);
      
      var keyset = keyczar.fromJson(sz_keyset);
      var encrypted = keyset.encrypt(message);
      
      return cb(null, encrypted);
    });
  };
};
