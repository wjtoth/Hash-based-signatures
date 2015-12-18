package wjtoth.MSS;

import hashing.Hash;
import signatures.PublicKey;

/**
 * Structure of Merkle Tree public key. Consists of the Hash value of the tree
 * root.
 * 
 * @author wjtoth
 *
 */
public class PublicKeyMerkle implements PublicKey {
    private final Hash root;

    public PublicKeyMerkle(Hash root) {
	this.root = root;
    }

    public Hash getRoot() {
	return this.root;
    }

    @Override
    public byte[] toByteArray() {
	return this.root.getData();
    }
}
