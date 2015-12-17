package wjtoth.MSS;

import org.apache.commons.lang3.ArrayUtils;

import hashing.Hash;
import signatures.PublicKey;
import signatures.Signature;

public class SignatureMerkle implements Signature {

    Signature sig1;
    PublicKey verificationKey;
    Hash[] auth;

    public SignatureMerkle(Signature sig1, PublicKey verificationKey, Hash[] auth) {
	this.sig1 = sig1;
	this.verificationKey = verificationKey;
	this.auth = auth;
    }

    public Hash[] getAuth() {
	return this.auth;
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
