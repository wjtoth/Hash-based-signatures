package ots;

import java.math.BigInteger;
import java.util.BitSet;

import hashing.Hash;
import hashing.HashFunction;
import signatures.PrivateKey;
import signatures.Signature;
import signatures.Signer;

/**
 * Signing algorithm for Winternitz signatures.
 *
 * @author wjtoth
 *
 */
public class SignerWinternitz implements Signer {

    private final HashFunction h;
    private final int k;
    private final int w;
    private final int kwratio;
    private final int t;

    /**
     *
     * @param hashFunction
     * @param messageBitLength
     * @param w
     *            the Winternitz parameter
     */
    public SignerWinternitz(HashFunction hashFunction, int messageBitLength, int w) {
	this.h = hashFunction;
	this.k = messageBitLength;
	this.w = w;
	this.kwratio = (int) Math.ceil((float) this.k / (float) w);
	this.t = WinternitzCommons.computeT(this.k, w, this.kwratio);
    }

    public Signature sign(String message, PrivateKey privateKey) throws Exception {
	if (!(privateKey instanceof PrivateKeyWinternitz)) {
	    throw new Exception("Wrong Type of Signing Key");
	}

	final PrivateKeyWinternitz privateKeyWinternitz = (PrivateKeyWinternitz) privateKey;
	final byte[] messageHashBytes = this.h.hash(message).toByteArray();
	final BitSet messageBits = new BitSet(this.k);
	messageBits.or(BitSet.valueOf(messageHashBytes));

	final BitSet[] b = new BitSet[this.t];

	// split messages binary into w sized blocks
	for (int i = 0; i < this.kwratio; ++i) {
	    b[i] = new BitSet(this.w);
	    b[i].or(messageBits.get(i * this.w, Math.min((i + 1) * this.w, messageBits.size())));
	}
	// compute checksum
	final BigInteger c = WinternitzCommons.computeCheckSum(b, this.w);
	// checksum interpreted as binary
	final BitSet cBinary = BitSet.valueOf(c.toByteArray());

	// split cBinary into w size blocks
	for (int i = this.kwratio; i < this.t; ++i) {
	    b[i] = new BitSet(this.w);
	    b[i].or(cBinary.get((i - this.kwratio) * this.w,
		    Math.min(((i - this.kwratio) + 1) * this.w, cBinary.size())));
	}

	final Hash[] sig = new Hash[this.t];
	// interpret blocks as integers and hash message blocks that many times
	for (int i = 0; i < this.t; ++i) {
	    final int bIntValue = b[i].length() > 0 ? new BigInteger(b[i].toByteArray()).intValue() : 0;
	    sig[i] = WinternitzCommons.powerhash(privateKeyWinternitz.getX(i), this.h, bIntValue);
	}
	return new SignatureWinternitz(sig);
    }
}
