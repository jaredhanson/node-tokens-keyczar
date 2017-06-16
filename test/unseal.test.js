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
          return cb(null, [ { secret: 'abcdef7890abcdef' } ]);
        });
      
        unseal = setup(keying);
      });
      
      var tkn;
      before(function(done) {
        var token = 'AIMIqG3eiQz7bQvB0gZ6HYoUtu7QnUOJJkxf-EniaWyMYvucFgM6jFfZ73WsWtR-ikLC8k7bLLFT';
        
        unseal(token, function(err, t) {
          tkn = t;
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
          usage: 'decrypt',
          algorithms: [ 'aes256-cbc' ],
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
