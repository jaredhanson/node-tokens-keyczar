var forge = require('node-forge');
var keyczar = require('keyczarjs');
var keyczar_util = require('keyczarjs/keyczar_util');


exports.toKeyset = function(publicKey, options) {
  var cert = forge.pki.certificateFromPem(publicKey);
  
  var _meta = {
    name: '',
    purpose: keyczar.PURPOSE_ENCRYPT,
    type: keyczar.TYPE_RSA_PUBLIC,
    encrypted: false,
    versions: [{
      exportable: false,
      status: 'PRIMARY',
      versionNumber: 1
    }]
  };
  var _zkey = keyczar_util._rsaPublicKeyToKeyczarJson(cert.publicKey);
  
  var json = JSON.stringify({
    meta: JSON.stringify(_meta),
    '1': _zkey
  });
  return keyczar.fromJson(json);
};
