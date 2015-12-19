package signatures;

/**
 * A structure consisting of a key generation algorithm, a signing algorithm,
 * and a verification algorithm. They should all coincide for functionality.
 *
 * @author wjtoth
 *
 */
public class SignatureScheme {

    private final KeyGenerator keyGenerator;
    private final Signer signer;
    private final Verifier verifier;

    public SignatureScheme(KeyGenerator keyGenerator, Signer signer, Verifier verifier) {
	this.keyGenerator = keyGenerator;
	this.signer = signer;
	this.verifier = verifier;
    }

    public KeyPair generateKeys() throws Exception {
	return this.keyGenerator.generateKeys();
    }

    public Signer getSigner() {
	return this.signer;
    }

    public Verifier getVerifier() {
	return this.verifier;
    }

    public Signature sign(String message, PrivateKey privateKey) throws Exception {
	return this.signer.sign(message, privateKey);
    }

    public boolean verify(String message, Signature signature, PublicKey publicKey) throws Exception {
	return this.verifier.verify(message, signature, publicKey);
    }
}
