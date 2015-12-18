package ots;

import org.apache.commons.lang3.ArrayUtils;

import hashing.Hash;
import signatures.Signature;

/**
 * Winternitz signature structure. Consistes of an array of hashes.
 * 
 * @author wjtoth
 *
 */
public class SignatureWinternitz implements Signature {

    Hash[] sig;

    public SignatureWinternitz(Hash[] sig) {
	this.sig = sig;
    }

    public Hash[] getSig() {
	return this.sig;
    }

    public Hash getSig(int i) {
	return this.sig[i];
    }

    @Override
    public byte[] toByteArray() {
	byte[] data = this.sig[0].toByteArray();
	for (int i = 1; i < this.sig.length; ++i) {
	    data = ArrayUtils.addAll(data, this.sig[i].toByteArray());
	}
	return data;
    }

}
