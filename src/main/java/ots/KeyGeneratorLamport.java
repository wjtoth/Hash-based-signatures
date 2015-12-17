package ots;

import java.math.BigInteger;
import java.security.SecureRandom;

import hashing.Hash;
import hashing.HashFunction;
import signatures.KeyGenerator;
import signatures.KeyPair;

public class KeyGeneratorLamport implements KeyGenerator {

    private final HashFunction h;
    private final int k;

    public KeyGeneratorLamport(HashFunction hashFunction, int messageBitLength) {
	this.h = hashFunction;
	this.k = messageBitLength;
    }

    @Override
    public KeyPair generateKeys() throws Exception {

	final BigInteger[] x1 = new BigInteger[this.k];
	final BigInteger[] x2 = new BigInteger[this.k];
	final Hash[] y1 = new Hash[this.k];
	final Hash[] y2 = new Hash[this.k];

	final SecureRandom secureRandom = new SecureRandom();

	for (int i = 0; i < this.k; ++i) {
	    x1[i] = new BigInteger(this.k, secureRandom);
	    y1[i] = this.h.hash(x1[i].toByteArray());
	    x2[i] = new BigInteger(this.k, secureRandom);
	    y2[i] = this.h.hash(x2[i].toByteArray());
	}

	final PrivateKeyLamport privateKeyLamport = new PrivateKeyLamport(x1, x2);
	final PublicKeyLamport publicKeyLamport = new PublicKeyLamport(y1, y2);
	return new KeyPair(publicKeyLamport, privateKeyLamport);
    }

}
