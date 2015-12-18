package wjtoth.MSS;

import com.tantaman.commons.concurrent.Parallel;

import hashing.HashFunction;
import signatures.SignatureScheme;

public class MerkleSSParallel extends MerkleSS {
    public MerkleSSParallel(HashFunction hashFunction, SignatureScheme signatureScheme, int height) {
	super(hashFunction, signatureScheme, height);
    }

    private void buildStacks() {
	Parallel.blockingFor(this.stacks, new Parallel.Operation<TreeHashStack>() {

	    @Override
	    public void perform(final TreeHashStack param) {
		param.update(2);
	    };

	});
    }

    private void refreshAuthNodes() {
	Parallel.For(this.stacks, new Parallel.Operation<TreeHashStack>() {
	    @Override
	    public void perform(TreeHashStack param) {
		final int h = param.maxheight;
		final int hPower = IntMath.binpower(h);
		if (((MerkleSSParallel.this.leaf + 1) % hPower) == 0) {
		    MerkleSSParallel.this.auth[h] = param.top();
		    final int startnode = (((MerkleSSParallel.this.leaf + 1) + hPower) ^ hPower)
			    % MerkleSSParallel.this.numberOfLeaves;
		    param.initialize(startnode, h);
		}
	    }
	});
    }

    @Override
    protected void traverseTree() {
	this.refreshAuthNodes();
	this.buildStacks();
	++this.leaf;
    }
}
