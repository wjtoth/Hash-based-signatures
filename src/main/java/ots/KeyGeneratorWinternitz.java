package ots;

import java.math.BigInteger;
import java.security.SecureRandom;

import hashing.Hash;
import hashing.HashFunction;
import signatures.KeyGenerator;
import signatures.KeyPair;

public class KeyGeneratorWinternitz implements KeyGenerator {

    HashFunction h;
    int k;
    int w;
    int kwratio;
    int t;

    public KeyGeneratorWinternitz(HashFunction hashFunction, int messageBitLength, int w) {
	this.h = hashFunction;
	this.k = messageBitLength;
	this.w = w;
	this.kwratio = (int) Math.ceil((float) this.k / (float) w);
	this.t = this.computeT(this.k, w, this.kwratio);
    }

    private int computeT(int k, int w, int kwratio) {
	final double log = BitManipulations.binlog(kwratio);
	final double sum = Math.floor(log) + 1 + w;
	return kwratio + (int) Math.ceil(sum / w);
    }

    private Hash concatAllAndHash(Hash[] y, HashFunction h) {
	final Hash hash = y[0];
	for (int i = 1; i < y.length; ++i) {
	    hash.concat(y[i]);
	}
	return h.hash(hash);
    }

    @Override
    public KeyPair generateKeys() throws Exception {
	final BigInteger[] x = new BigInteger[this.t];
	final Hash[] y = new Hash[this.t];
	final SecureRandom secureRandom = new SecureRandom();
	for (int i = 0; i < this.t; ++i) {
	    x[i] = new BigInteger(this.k, secureRandom);
	    y[i] = this.powerhash(x[i], this.h, (int) Math.pow(2, this.w) - 1);
	}
	final Hash finalY = this.concatAllAndHash(y, this.h);
	final PrivateKeyWinternitz privateKeyWinternitz = new PrivateKeyWinternitz(x);
	final PublicKeyWinternitz publicKeyWinternitz = new PublicKeyWinternitz(finalY);
	return new KeyPair(publicKeyWinternitz, privateKeyWinternitz);
    }

    private Hash powerhash(BigInteger x, HashFunction h, int power) throws Exception {
	if (power == 0) {
	    return new Hash(x.toByteArray());
	}
	Hash hash = h.hash(x.toByteArray());
	for (int i = 1; i < power; ++i) {
	    hash = h.hash(hash);
	}
	return hash;
    }
}
