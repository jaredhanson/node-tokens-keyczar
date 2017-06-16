var keyczar = require('keyczarjs');
var keyczar_util = require('keyczarjs/keyczar_util');


exports.toKeyset = function(key, hmacKey, options) {
  var _meta = {
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
  var _key = {
    aesKeyString: keyczar_util.encodeBase64Url(key),
    size: options.size,
    mode: 'CBC',
    hmacKey: {
      hmacKeyString: keyczar_util.encodeBase64Url(hmacKey),
      size: 256
    }
  };
  
  var json = JSON.stringify({
    meta: JSON.stringify(_meta),
    '1': JSON.stringify(_key)
  });
  return keyczar.fromJson(json);
};
