package wjtoth.MSS;

import org.apache.commons.lang3.ArrayUtils;

import hashing.Hash;
import signatures.PublicKey;
import signatures.Signature;

/**
 * The structure of a Merkle tree signature. See constructor comments for
 * semantics related to the fields.
 *
 * @author wjtoth
 *
 */
public class SignatureMerkle implements Signature {

    Signature sig1;
    PublicKey verificationKey;
    Hash[] auth;
    int index;

    /**
     *
     * @param sig1
     *            The signature of the message under the One Time Signature
     *            scheme being used with the Merkle tree using the KeyPair
     *            associated with the current leaf.
     * @param verificationKey
     *            The one time signature scheme verificationKey associated with
     *            sig1 and the current leaf.
     * @param auth
     *            An array of hashes used to compute the path back from the root
     *            auth[0] is sibling of leaf hash
     * @param index
     *            index value of leaf used to sign
     */
    public SignatureMerkle(Signature sig1, PublicKey verificationKey, Hash[] auth, int index) {
	this.sig1 = sig1;
	this.verificationKey = verificationKey;
	this.auth = auth;
	this.index = index;
    }

    public Hash[] getAuth() {
	return this.auth;
    }

    public int getIndex() {
	return this.index;
    }

    public Signature getSig1() {
	return this.sig1;
    }

    public PublicKey getVerificationKey() {
	return this.verificationKey;
    }

    @Override
    public byte[] toByteArray() {
	byte[] data = this.sig1.toByteArray();
	data = ArrayUtils.addAll(data, this.verificationKey.toByteArray());
	for (final Hash element : this.auth) {
	    data = ArrayUtils.addAll(data, element.toByteArray());
	}
	return data;
    }

}
