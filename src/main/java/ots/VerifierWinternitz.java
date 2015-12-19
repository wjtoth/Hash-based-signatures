package ots;

import java.math.BigInteger;
import java.util.BitSet;

import hashing.Hash;
import hashing.HashFunction;
import signatures.PublicKey;
import signatures.Signature;
import signatures.Verifier;

/**
 * Verification algorithm for Winternitz one time signatures
 *
 * @author wjtoth
 *
 */
public class VerifierWinternitz implements Verifier {

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
    public VerifierWinternitz(HashFunction hashFunction, int messageBitLength, int w) {
	this.h = hashFunction;
	this.k = messageBitLength;
	this.w = w;
	this.kwratio = (int) Math.ceil((float) this.k / (float) w);
	this.t = WinternitzCommons.computeT(this.k, w, this.kwratio);
    }

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
	final BigInteger c = WinternitzCommons.computeCheckSum(b, this.w);
	// The integer c interpreted as binary
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
	    phi[i] = WinternitzCommons.powerhash(signatureWinternitz.getSig(i), this.h,
		    (int) Math.pow(2, this.w - 1 - bIntValue));
	}
	return WinternitzCommons.concatAllAndHash(phi, this.h).equals(publicKeyWinternitz.getY());
    }

}
