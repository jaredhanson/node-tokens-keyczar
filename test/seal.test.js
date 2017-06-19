var keyczar = require('keyczarjs');
var keyczar_util = require('keyczarjs/keyczar_util');
var setup = require('../lib/seal');
var fs = require('fs');
var forge = require('node-forge');
var sinon = require('sinon');
var expect = require('chai').expect;


describe('seal', function() {
  
  describe('using defaults', function() {
    var seal, keying;
    
    before(function() {
      keying = sinon.spy(function(q, cb){
        if (!q.recipient) {
          if (q.usage == 'encrypt') {
            return cb(null, [ { secret: 'abcdef7890abcdef', algorithm: 'aes128-cbc' } ]);
          } else {
            return cb(null, [ { secret: 'abcdef7890abcdefef7890abcdef7890' } ]);
          }
        }
        
        switch (q.recipient.id) {
        case 'https://api.example.com/rsa-2048':
          return cb(null, [ { publicKey: fs.readFileSync(__dirname + '/keys/rsa-2048/cert.pem'), algorithm: 'rsa-oaep' } ]);
        }
      });
      
      seal = setup(keying);
    });
    
    
    describe('encrypting to self', function() {
      this.timeout(10000);
      
      var token;
      before(function(done) {
        seal({ foo: 'bar' }, function(err, t) {
          token = t;
          done(err);
        });
      });
      
      after(function() {
        keying.reset();
      });
      
      it('should query for key', function() {
        expect(keying.callCount).to.equal(2);
        var call = keying.getCall(0);
        expect(call.args[0]).to.deep.equal({
          usage: 'encrypt',
          recipient: undefined,
          algorithms: [ 'aes128-cbc' ]
        });
        
        call = keying.getCall(1);
        expect(call.args[0]).to.deep.equal({
          usage: 'sign',
          recipient: undefined,
          algorithms: [ 'hmac-sha256' ]
        });
      });
      
      it('should generate a token', function() {
        expect(token.length).to.be.above(0);
        expect(token.substr(0, 1)).to.equal('A');
      });
      
      describe('verifying claims', function() {
        var claims;
        before(function() {
          var szkeyset = JSON.stringify({
            meta: JSON.stringify({
              name: '',
              purpose: keyczar.PURPOSE_DECRYPT_ENCRYPT,
              type: keyczar.TYPE_AES,
              encrypted: false,
              versions: [{
                exportable: false,
                status: 'PRIMARY',
                versionNumber: 1
              }]
            }),
            '1': JSON.stringify({
              mode: 'CBC',
              aesKeyString: keyczar_util.encodeBase64Url('abcdef7890abcdef'),
              size: 128,
              hmacKey: {
                hmacKeyString: keyczar_util.encodeBase64Url('abcdef7890abcdefef7890abcdef7890'),
                size: 256
              }
            })
          });
          
          var keyset = keyczar.fromJson(szkeyset);
          var payload = keyset.decrypt(token);
          
          claims = JSON.parse(payload);
        });
        
        it('should be correct', function() {
          expect(claims).to.be.an('object');
          expect(claims.foo).to.equal('bar');
        });
      });
    }); // encrypting to self
    
    describe('encrypting to audience with 2048-bit RSA', function() {
      this.timeout(10000);
      
      var token;
      before(function(done) {
        var audience = [ {
          id: 'https://api.example.com/rsa-2048'
        } ];
        
        seal({ foo: 'bar' }, { audience: audience }, function(err, t) {
          token = t;
          done(err);
        });
      });
      
      after(function() {
        keying.reset();
      });
      
      it('should query for key', function() {
        expect(keying.callCount).to.equal(2);
        var call = keying.getCall(0);
        expect(call.args[0]).to.deep.equal({
          usage: 'encrypt',
          recipient: {
            id: 'https://api.example.com/rsa-2048'
          },
          algorithms: [ 'aes128-cbc' ]
        });
        
        call = keying.getCall(1);
        expect(call.args[0]).to.deep.equal({
          usage: 'sign',
          recipient: {
            id: 'https://api.example.com/rsa-2048'
          },
          algorithms: [ 'hmac-sha256' ]
        });
      });
      
      it('should generate a token', function() {
        expect(token.length).to.be.above(0);
        expect(token.substr(0, 1)).to.equal('A');
      });
      
      describe('verifying claims', function() {
        var claims;
        before(function() {
          var data = fs.readFileSync(__dirname + '/keys/rsa-2048/private-key.pem');
          var key = forge.pki.privateKeyFromPem(data);
          
          var szkeyset = JSON.stringify({
            meta: JSON.stringify({
              name: '',
              purpose: keyczar.PURPOSE_DECRYPT_ENCRYPT,
              type: keyczar.TYPE_RSA_PRIVATE,
              encrypted: false,
              versions: [{
                exportable: false,
                status: 'PRIMARY',
                versionNumber: 1
              }]
            }),
            '1': keyczar_util._rsaPrivateKeyToKeyczarJson(key)
          });
          
          var keyset = keyczar.fromJson(szkeyset);
          var payload = keyset.decrypt(token);
          
          claims = JSON.parse(payload);
        });
        
        it('should be correct', function() {
          expect(claims).to.be.an('object');
          expect(claims.foo).to.equal('bar');
        });
      });
    }); // encrypting to audience with 2048-bit RSA
    
  }); // using defaults
  
}); // seal
