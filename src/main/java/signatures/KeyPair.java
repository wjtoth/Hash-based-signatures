package signatures;

/**
 * Structure collection a public and private key pair. Output of a KeyGenerator.
 * 
 * @author wjtoth
 *
 */
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
