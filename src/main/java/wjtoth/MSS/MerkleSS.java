package wjtoth.MSS;

import java.util.ArrayList;
import java.util.Stack;

import hashing.Hash;
import hashing.HashFunction;
import signatures.PrivateKey;
import signatures.PublicKey;
import signatures.Signature;
import signatures.SignatureScheme;

public class MerkleSS {

    public class TreeHashStack {
	Stack<MerkleNode> stack;
	int maxheight;
	int leaf;
	int index;

	public TreeHashStack(int start, int maxheight, int index) {
	    this.leaf = start;
	    this.maxheight = maxheight;
	    this.stack = new Stack<MerkleNode>();
	    this.index = index;
	}

	private int consolidate(MerkleNode stackRight, MerkleNode stackLeft) {
	    final Hash parentHash = MerkleSS.this.hashFunction.hash(stackLeft.getHash().concat(stackRight.getHash()));
	    final int parentHeight = stackRight.getHeight() + 1;
	    // found auth node
	    if (parentHeight == this.maxheight) {
		MerkleSS.this.auth[this.index] = parentHash;
		return 0;
	    }
	    this.stack.push(new MerkleNode(parentHash, parentHeight));
	    return 1;
	}

	private int newLeaf(int height) {
	    this.stack.push(new MerkleNode(MerkleSS.this.leafCalc(this.leaf), height));
	    ++this.leaf;
	    return 0;
	}

	private int operate() {
	    if (this.stack.size() >= 2) {
		// top node of stack
		final MerkleNode stackRight = this.stack.pop();
		// second from top node of stack
		final MerkleNode stackLeft = this.stack.pop();
		if (stackRight.getHeight() == stackLeft.getHeight()) {
		    return this.consolidate(stackRight, stackLeft);
		} else {
		    this.stack.push(stackLeft);
		    this.stack.push(stackRight);
		    return this.newLeaf(this.stack.peek().getHeight());
		}
	    } else {
		final int height = this.stack.size() == 1 ? this.stack.peek().getHeight() : 0;
		return this.newLeaf(height);
	    }
	}

	public Hash top() {
	    return this.stack.peek().getHash();
	}

	// runs n iterations of operate
	private void update(int n) {
	    int i = 0;
	    int retval = 1;
	    while ((retval == 1) && (i < n)) {
		retval = this.operate();
		++i;
	    }
	}
    }

    private final HashFunction hashFunction;
    private final SignatureScheme signatureScheme;
    private final int height;
    private int leaf;
    private final int numberOfLeaves;
    private final ArrayList<TreeHashStack> stacks;

    private final Hash[] auth;

    // TODO figure out how to do this "online"
    // should become clear once things are put together
    private final PrivateKey[] signingKeys;
    private final PublicKey[] verificationKeys;

    public MerkleSS(HashFunction hashFunction, SignatureScheme signatureScheme, int height) {
	this.hashFunction = hashFunction;
	this.signatureScheme = signatureScheme;
	this.height = height;
	this.leaf = 0;
	this.numberOfLeaves = (int) Math.pow(2, height);
	this.stacks = new ArrayList<TreeHashStack>(this.height);
	this.auth = new Hash[height];
	this.signingKeys = new PrivateKey[this.numberOfLeaves];
	this.verificationKeys = new PublicKey[this.numberOfLeaves];
    }

    private void buildStacks() {
	for (int h = 0; h < this.height; ++h) {
	    this.stacks.get(h).update(2);
	}
    }

    public PublicKey generatePublicKey() {
	return null;
    }

    private Hash leafCalc(int leaf) {
	return this.hashFunction.hash(this.verificationKeys[leaf]);
    }

    private void refreshAuthNodes() {
	for (int h = 0; h < this.height; ++h) {
	    final int hPower = (int) Math.pow(2, h);
	    if (((this.leaf + 1) % hPower) == 0) {
		this.auth[h] = this.stacks.get(h).top();
		// TODO not sure about this
		final int startnode = (this.leaf + 1 + hPower) ^ hPower;
		this.stacks.set(h, new TreeHashStack(startnode, h, h));
	    }
	}
    }

    // TODO implement
    public Signature sign() throws Exception {
	if (this.leaf >= this.numberOfLeaves) {
	    throw new Exception("out of signing leaves");
	}
	// sig' = signatureScheme.sign(leaf)
	// sig = new MerkleSignature(sig', leafCalc(leaf), auth)
	// traverseTree
	// return sig
	return null;
    }

    private void traverseTree() {
	this.refreshAuthNodes();
	this.buildStacks();
	++this.leaf;
    }
}