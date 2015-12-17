package wjtoth.MSS;

import hashing.Hash;

/**
 *
 * @author wjtoth
 *
 *         Stores data pertinent to a node in a Merkle tree
 *
 */
public class MerkleNode {
    private final Hash hash;
    private final int height;

    public MerkleNode(Hash hash, int height) {
	this.hash = hash;
	this.height = height;
    }

    public Hash getHash() {
	return this.hash;
    }

    public int getHeight() {
	return this.height;
    }
}
