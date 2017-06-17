/**
 * Keyczar token implementation.
 */

// https://tersesystems.com/2015/10/05/effective-cryptography-in-the-jvm/
// https://github.com/google/keyczar
// https://groups.google.com/forum/#!topic/keyczar-discuss/BLEY_Dp4_7U
// https://dzone.com/articles/easy-encryption-java-and-pytho

exports.seal = require('./seal');
exports.unseal = require('./unseal');
