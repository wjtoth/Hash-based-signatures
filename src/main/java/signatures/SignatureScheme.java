package signatures;

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

    public Signature sign(String message, PrivateKey privateKey) throws Exception {
	return this.signer.sign(message, privateKey);
    }

    public boolean verify(String message, Signature signature, PublicKey publicKey) throws Exception {
	return this.verifier.verify(message, signature, publicKey);
    }
}
