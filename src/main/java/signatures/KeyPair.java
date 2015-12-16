package signatures;

public class KeyPair {
    PublicKey publicKey;
    PrivateKey privateKey;

    public KeyPair(PublicKey publicKey, PrivateKey privateKey) {
	this.publicKey = publicKey;
	this.privateKey = privateKey;
    }

    public PrivateKey getPrivateKey() {
	return this.privateKey;
    }

    public PublicKey getPublicKey() {
	return this.publicKey;
    }
}
