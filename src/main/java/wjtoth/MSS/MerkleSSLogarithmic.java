package wjtoth.MSS;

import hashing.HashFunction;
import signatures.SignatureScheme;

public class MerkleSSLogarithmic extends MerkleSS {

    public MerkleSSLogarithmic(HashFunction hashFunction, SignatureScheme signatureScheme, int height) {
	super(hashFunction, signatureScheme, height);
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
	    this.stacks.get(focus).update(1);
	}
    }

    private void refreshAuthNodes() {
	for (int h = 0; h < this.height; ++h) {
	    final int hPower = (int) Math.pow(2, h);
	    if (((this.leaf + 1) % hPower) == 0) {
		this.auth[h] = this.stacks.get(h).top();
		// TODO not sure about this
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
