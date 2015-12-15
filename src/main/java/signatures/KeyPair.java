package signatures;

public class KeyPair {
	PublicKey publicKey;
	PrivateKey privateKey;
	
	public KeyPair(PublicKey publicKey, PrivateKey privateKey) {
		this.publicKey = publicKey;
		this.privateKey = privateKey;
	}
	
	PublicKey getPublicKey() {
		return publicKey;
	}
	
	PrivateKey getPrivateKey() {
		return privateKey;
	}
}
