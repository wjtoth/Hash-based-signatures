package wjtoth.MSS;

import hashing.HashFunction;

/**
 * An implemenation of the tree traversal algorithm given by Szydlo is
 * "Merkle tree traversal in log space and time"
 *
 * @author wjtoth
 *
 */
public class MerkleSSLogarithmic extends MerkleSS {

    public MerkleSSLogarithmic(HashFunction hashFunction, LeafOracle leafOracle, int height) {
	super(hashFunction, leafOracle, height);
    }

    private void buildStacks() {
	for (int i = 0; i < ((2 * this.height) - 1); ++i) {
	    int minL = Integer.MAX_VALUE;
	    int focus = 0;
	    for (int h = 0; h < this.height; ++h) {
		final TreeHashStack stack = this.stacks.get(h);
		if (stack.low() < minL) {
		    minL = stack.low();
		    focus = h;
		}
	    }
	    try {
		this.stacks.get(focus).update(1);
	    } catch (final Exception e) {
		e.printStackTrace();
	    }
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
    protected void traverseTree() {
	this.refreshAuthNodes();
	this.buildStacks();
	++this.leaf;
    }

}
