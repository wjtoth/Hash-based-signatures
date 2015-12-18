package ots;

import java.util.BitSet;

import hashing.Hash;
import hashing.HashFunction;
import signatures.PublicKey;
import signatures.Signature;
import signatures.Verifier;

/**
 * Verification algorithm for Lamport one time signatures
 *
 * @author wjtoth
 *
 */
public class VerifierLamport implements Verifier {

    private final int k;
    private final HashFunction h;

    /**
     *
     * @param hashFunction
     * @param messageBitLength
     *            max length of messages, should not exceed hashFunciton bit
     *            length and optimally is equal to it
     */
    public VerifierLamport(HashFunction hashFunction, int messageBitLength) {
	this.k = messageBitLength;
	this.h = hashFunction;
    }

    @Override
    public boolean verify(String message, Signature signature, PublicKey publicKey) throws Exception {
	if (!(publicKey instanceof PublicKeyLamport)) {
	    throw new Exception("Wrong Type of Signing Key");
	}

	final PublicKeyLamport publicKeyLamport = (PublicKeyLamport) publicKey;

	if (!(signature instanceof SignatureLamport)) {
	    throw new Exception("Wrong Type of Signature");
	}

	final SignatureLamport signatureLamport = (SignatureLamport) signature;
	final BitSet messageBits = new BitSet(this.k);
	messageBits.or(BitSet.valueOf(message.getBytes()));

	// verification algorithm
	for (int i = 0; i < this.k; ++i) {
	    final Hash hashX = this.h.hash(signatureLamport.getSig(i).toByteArray());
	    final Hash hashY = !messageBits.get(i) ? publicKeyLamport.getY1(i) : publicKeyLamport.getY2(i);
	    if (!hashX.equals(hashY)) {
		return false;
	    }
	}

	return true;
    }

}
