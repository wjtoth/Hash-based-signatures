package ots;

import java.math.BigInteger;
import java.security.SecureRandom;

import hashing.Hash;
import hashing.HashFunction;
import signatures.KeyGenerator;
import signatures.KeyPair;
import wjtoth.MSS.IntMath;

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
	this.t = WinternitzCommons.computeT(this.k, w, this.kwratio);
    }

    @Override
    public KeyPair generateKeys() throws Exception {
	final BigInteger[] x = new BigInteger[this.t];
	final Hash[] y = new Hash[this.t];
	final SecureRandom secureRandom = new SecureRandom();
	for (int i = 0; i < this.t; ++i) {
	    x[i] = new BigInteger(this.k, secureRandom);
	    y[i] = WinternitzCommons.powerhash(x[i], this.h, IntMath.binpower(this.w) - 1);
	}
	final Hash finalY = WinternitzCommons.concatAllAndHash(y, this.h);
	final PrivateKeyWinternitz privateKeyWinternitz = new PrivateKeyWinternitz(x);
	final PublicKeyWinternitz publicKeyWinternitz = new PublicKeyWinternitz(finalY);
	return new KeyPair(publicKeyWinternitz, privateKeyWinternitz);
    }

}
