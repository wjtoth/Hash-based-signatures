package wjtoth.MSS;

import com.tantaman.commons.concurrent.Parallel;

import hashing.HashFunction;

/**
 * A parallelized version of the MerkleSSClassical tree traversal.
 *
 * @author wjtoth
 *
 */
public class MerkleSSParallel extends MerkleSS {
    public MerkleSSParallel(HashFunction hashFunction, LeafOracle leafOracle, int height) {
	super(hashFunction, leafOracle, height);
    }

    private void buildStacks() {
	Parallel.blockingFor(this.stacks, new Parallel.Operation<TreeHashStack>() {
	    public void perform(final TreeHashStack param) {
		try {
		    param.update(2);
		} catch (final Exception e) {
		    e.printStackTrace();
		}
	    };

	});
    }

    private void refreshAuthNodes() {
	Parallel.For(this.stacks, new Parallel.Operation<TreeHashStack>() {
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
