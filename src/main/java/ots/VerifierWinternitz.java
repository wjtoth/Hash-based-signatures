package ots;

import java.math.BigInteger;
import java.util.BitSet;

import org.apache.commons.lang3.ArrayUtils;

import hashing.Hash;
import hashing.HashFunction;
import signatures.PublicKey;
import signatures.Signature;
import signatures.Verifier;
import wjtoth.MSS.IntMath;

public class VerifierWinternitz implements Verifier {

    private final HashFunction h;
    private final int k;
    private final int w;
    private final int kwratio;
    private final int t;

    public VerifierWinternitz(HashFunction hashFunction, int messageBitLength, int w) {
	this.h = hashFunction;
	this.k = messageBitLength;
	this.w = w;
	this.kwratio = (int) Math.ceil((float) this.k / (float) w);
	this.t = this.computeT(this.k, w, this.kwratio);
    }

    private BigInteger computeCheckSum(BitSet[] b) {
	BigInteger c = BigInteger.ZERO;
	final long twoW = IntMath.binpower((long) this.w);
	final BigInteger twoWBI = BigInteger.valueOf(twoW);
	ArrayUtils.toString(b);
	for (final BitSet element : b) {
	    // b may not be full when this is called
	    if (element == null) {
		break;
	    }
	    c = c.add(twoWBI);
	    if (element.length() > 0) {
		final BigInteger bBI = new BigInteger(element.toByteArray());
		c = c.add(bBI);
	    }
	}
	return c;
    }

    private int computeT(int k, int w, int kwratio) {
	final double log = IntMath.binlog(kwratio);
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

    private Hash powerhash(Hash hash, HashFunction h, int power) throws Exception {
	Hash returnHash = h.hash(hash);
	for (int i = 0; i < power; ++i) {
	    returnHash = h.hash(returnHash);
	}
	return returnHash;
    }

    @Override
    public boolean verify(String message, Signature signature, PublicKey publicKey) throws Exception {
	if (!(publicKey instanceof PublicKeyWinternitz)) {
	    throw new Exception("Wrong Type of Signing Key");
	}

	final PublicKeyWinternitz publicKeyWinternitz = (PublicKeyWinternitz) publicKey;

	if (!(signature instanceof SignatureWinternitz)) {
	    throw new Exception("Wrong Type of Signature");
	}

	final SignatureWinternitz signatureWinternitz = (SignatureWinternitz) signature;
	final byte[] messageHashBytes = this.h.hash(message).toByteArray();
	final BitSet messageBits = new BitSet(this.k);
	messageBits.or(BitSet.valueOf(messageHashBytes));

	final BitSet[] b = new BitSet[this.t];
	for (int i = 0; i < this.kwratio; ++i) {
	    b[i] = new BitSet(this.w);
	    b[i].or(messageBits.get(i * this.w, Math.min((i + 1) * this.w, messageBits.size())));
	}
	final BigInteger c = this.computeCheckSum(b);
	final BitSet cBinary = BitSet.valueOf(c.toByteArray());
	for (int i = this.kwratio; i < this.t; ++i) {
	    b[i] = new BitSet(this.w);
	    b[i].or(cBinary.get((i - this.kwratio) * this.w,
		    Math.min(((i - this.kwratio) + 1) * this.w, cBinary.size())));
	}

	// verification algorithm
	final Hash[] phi = new Hash[this.t];
	for (int i = 0; i < this.t; ++i) {
	    final int bIntValue = b[i].length() > 0 ? new BigInteger(b[i].toByteArray()).intValue() : 0;
	    phi[i] = this.powerhash(signatureWinternitz.getSig(i), this.h, (int) Math.pow(2, this.w - 1 - bIntValue));
	}
	return this.concatAllAndHash(phi, this.h).equals(publicKeyWinternitz.getY());
    }

}
