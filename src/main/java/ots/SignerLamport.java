package ots;

import java.math.BigInteger;
import java.util.BitSet;

import signatures.PrivateKey;
import signatures.Signature;
import signatures.Signer;

/**
 * Lamport signing algorithm
 *
 * @author wjtoth
 *
 */
public class SignerLamport implements Signer {

    private final int k;

    public SignerLamport(int messageBitLength) {
	this.k = messageBitLength;
    }

    public Signature sign(String message, PrivateKey privateKey) throws Exception {
	if (!(privateKey instanceof PrivateKeyLamport)) {
	    throw new Exception("Wrong Type of Signing Key");
	}

	final PrivateKeyLamport privateKeyLamport = (PrivateKeyLamport) privateKey;
	final BitSet messageBits = new BitSet(this.k);
	messageBits.or(BitSet.valueOf(message.getBytes()));

	// signing algorithm
	final BigInteger[] sig = new BigInteger[this.k];
	for (int i = 0; i < this.k; ++i) {
	    sig[i] = !messageBits.get(i) ? privateKeyLamport.getX1(i) : privateKeyLamport.getX2(i);
	}
	return new SignatureLamport(sig);
    }

}
