package wjtoth.MSS;

import hashing.Hash;
import hashing.HashFunction;
import signatures.PublicKey;
import signatures.Signature;
import signatures.Verifier;

public class VerifierMerkle implements Verifier {

    private final HashFunction h;
    private final Verifier verifier;

    public VerifierMerkle(HashFunction hashFunction, Verifier verifier) {
	this.h = hashFunction;
	this.verifier = verifier;
    }

    @Override
    public boolean verify(String message, Signature signature, PublicKey publicKey) throws Exception {
	if (!(publicKey instanceof PublicKeyMerkle)) {
	    throw new Exception("Wrong Type of Signing Key");
	}

	final PublicKeyMerkle publicKeyMerkle = (PublicKeyMerkle) publicKey;

	if (!(signature instanceof SignatureMerkle)) {
	    throw new Exception("Wrong Type of Signature");
	}

	final SignatureMerkle signatureMerkle = (SignatureMerkle) signature;

	if (!this.verifier.verify(message, signatureMerkle.getSig1(), signatureMerkle.getVerificationKey())) {
	    return false;
	}

	Hash hash = this.h.hash(signatureMerkle.getVerificationKey());
	final Hash[] auth = signatureMerkle.getAuth();
	final int s = signatureMerkle.getIndex();
	for (int i = 0; i < auth.length; ++i) {
	    final int heightPow = IntMath.binpower(i);
	    if (((s / heightPow) % 2) == 0) {
		hash = this.h.hash(hash.concat(auth[i]));
	    } else {
		hash = this.h.hash(auth[i].concat(hash.toByteArray()));
	    }
	}

	return hash.equals(publicKeyMerkle.getRoot());
    }

}
