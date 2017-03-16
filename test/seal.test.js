var keyczar = require('keyczarjs');
var keyczar_util = require('keyczarjs/keyczar_util');
var setup = require('../lib/seal');
var sinon = require('sinon');
var expect = require('chai').expect;


describe('seal', function() {
  
  describe('using defaults', function() {
    var seal, keying;
    
    before(function() {
      keying = sinon.spy(function(q, cb){
        if (q.recipients) {
          var recipient = q.recipients[0];
          return cb(null, [ { secret: recipient.secret } ]);
        }
        
        return cb(null, [ { id: 'k1', secret: 'abcdef7890abcdef' } ]);
      });
      
      seal = setup(keying);
    });
    
    
    describe('encrypting arbitrary claims', function() {
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
        expect(keying.callCount).to.equal(1);
        var call = keying.getCall(0);
        expect(call.args[0]).to.deep.equal({
          recipients: undefined,
          usage: 'encrypt',
          algorithms: [ 'aes256-cbc' ],
          length: 16
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
                hmacKeyString: keyczar_util.encodeBase64Url('abcdef7890abcdef' + 'abcdef7890abcdef'),
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
    }); // encrypting arbitrary claims
    
  });
  
});
