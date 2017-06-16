/* global describe, it */

var setup = require('../lib/unseal');
var sinon = require('sinon');
var expect = require('chai').expect;


describe('unseal', function() {
  
  describe('using defaults', function() {
    var unseal, keying;
    
    describe('unsealing', function() {
      before(function() {
        keying = sinon.spy(function(q, cb){
          if (q.usage == 'decrypt') {
            return cb(null, [ { secret: 'abcdef7890abcdef' } ]);
          } else {
            return cb(null, [ { secret: 'abcdef7890abcdefef7890abcdef7890' } ]);
          }
        });
      
        unseal = setup(keying);
      });
      
      var tkn;
      before(function(done) {
        var token = 'AFbSEQIlizeCtojN2JaSd1VgXSBApWdXLZ8Bb4-ArOvs6wN-SazhUJFFUX4YQxUsM-m-ZMVM72bo';
        
        unseal(token, function(err, t) {
          tkn = t;
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
          usage: 'decrypt',
          algorithms: [ 'aes128-cbc' ],
        });
        
        call = keying.getCall(1);
        expect(call.args[0]).to.deep.equal({
          usage: 'verify',
          algorithms: [ 'hmac-sha256' ],
        });
      });
      
      it('should unseal token', function() {
        expect(tkn).to.be.an('object');
        expect(Object.keys(tkn)).to.have.length(2);
        
        expect(tkn).to.deep.equal({
          headers: {
          },
          claims: {
            foo: 'bar'
          }
        });
      });
    }); // unsealing
    
  }); // using defaults
  
});
