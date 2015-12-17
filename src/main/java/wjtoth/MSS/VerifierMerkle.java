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
	System.out.println("OTS CHECKS OUT");
	Hash hash = this.h.hash(signatureMerkle.getVerificationKey());
	final Hash[] auth = signatureMerkle.getAuth();
	for (final Hash element : auth) {
	    hash = this.h.hash(hash.concat(element));
	}
	return hash.equals(publicKeyMerkle.getRoot());
    }

}
