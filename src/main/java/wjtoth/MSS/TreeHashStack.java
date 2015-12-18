package wjtoth.MSS;

import java.util.Stack;

import hashing.Hash;
import hashing.HashFunction;

public class TreeHashStack {
    Stack<MerkleNode> stack;
    int maxheight;
    int leaf;

    HashFunction hashFunction;
    LeafCalc leafCalc;

    public TreeHashStack(int start, int maxheight, HashFunction hashFunction, LeafCalc leafCalc) {
	this.hashFunction = hashFunction;
	this.leafCalc = leafCalc;
	this.stack = new Stack<MerkleNode>();
	this.initialize(start, maxheight);
    }

    private int consolidate(MerkleNode stackRight, MerkleNode stackLeft) {
	final Hash parentHash = this.hashFunction.hash(stackLeft.getHash().concat(stackRight.getHash()));
	final int parentHeight = stackRight.getHeight() + 1;

	this.stack.push(new MerkleNode(parentHash, parentHeight));
	// found auth node
	if (parentHeight == this.maxheight) {
	    return 0;
	}
	return 1;
    }

    public TreeHashStack initialize(int start, int maxheight) {
	this.leaf = start;
	this.maxheight = maxheight;
	this.stack.clear();
	return this;
    }

    private int newLeaf() {
	this.stack.push(new MerkleNode(this.leafCalc.computeLeaf(this.leaf), 0));
	if (this.stack.peek().getHeight() == this.maxheight) {
	    return 0;
	}
	++this.leaf;
	return 1;
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
		return this.newLeaf();
	    }
	} else {
	    return this.newLeaf();
	}
    }

    public void push(MerkleNode merkleNode) {
	this.stack.push(merkleNode);
    }

    public Hash top() {
	return this.stack.peek().getHash();
    }

    // runs n iterations of operate
    public void update(int n) {
	if ((this.stack.size() > 0) && (this.stack.peek().getHeight() == this.maxheight)) {
	    return;
	}
	int i = 0;
	int retval = 1;
	while ((retval == 1) && (i < n)) {
	    retval = this.operate();
	    ++i;
	}
    }
}
