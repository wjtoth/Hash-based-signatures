package wjtoth.MSS;

import hashing.HashFunction;

/**
 * An implementation of the original tree traversal algorithm given by Merkle in
 * his PhD dissertation.
 *
 * @author wjtoth
 *
 */
public class MerkleSSClassical extends MerkleSS {

    public MerkleSSClassical(HashFunction hashFunction, LeafOracle leafOracle, int height) {
	super(hashFunction, leafOracle, height);
    }

    private void buildStacks() throws Exception {
	for (int h = 0; h < this.height; ++h) {
	    this.stacks.get(h).update(2);
	}
    }

    private void refreshAuthNodes() {
	for (int h = 0; h < this.height; ++h) {
	    final int hPower = IntMath.binpower(h);
	    if (((this.leaf + 1) % hPower) == 0) {
		this.auth[h] = this.stacks.get(h).top();
		final int startnode = (((this.leaf + 1) + hPower) ^ hPower) % this.numberOfLeaves;
		this.stacks.get(h).initialize(startnode, h);
	    }
	}
    }

    @Override
    protected void traverseTree() throws Exception {
	this.refreshAuthNodes();
	this.buildStacks();
	++this.leaf;
    }
}
