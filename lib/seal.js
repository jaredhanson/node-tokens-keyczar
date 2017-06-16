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
    
    var audience = options.audience || [];
    if (audience.length > 1) {
      return cb(new Error('Unable to seal iron tokens for multiple recipients'));
    }
    
    
    var query  = {
      recipient: audience[0],
      usage: 'encrypt',
      algorithms: [ 'aes256-cbc' ],
      length: 16
    }
    
    keying(query, function(err, keys) {
      if (err) { return cb(err); }
      
      /*
      // Create an asymmetric key
      var private = keyczar.create(keyczar.TYPE_RSA_PRIVATE);
      var public = private.exportPublicKey();
      var privateSerialized = private.toJson();
      
      console.log('######');
      console.log('-- private:')
      console.log(private)
      console.log('-- public:')
      console.log(public)
      console.log('-- privateSerialized:')
      console.log(privateSerialized)
      console.log('######');
      
      var plaintext = 'Hello, world!'
      
      //var session = keyczar.createSessionCrypter(public);
      //var encrypted = session.encrypt(plaintext);
      //var sessionMaterial = session.sessionMaterial;
      
      //console.log(session);
      //console.log(encrypted);
      //console.log(sessionMaterial);
      
      return;
      */
      
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
