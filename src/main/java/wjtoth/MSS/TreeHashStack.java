package wjtoth.MSS;

import java.util.Stack;

import hashing.Hash;
import hashing.HashFunction;

/**
 * This data structure is used to simulate the common treehash algorithm of the
 * literature. consolidate and newLeaf represent the two cases of a single unit
 * of computation of treehash. update(n) performs n units of tree hash
 * computation. computation stops when it has found a node of maxheight. This
 * note roots a subtree of the merkle tree for which startnode from the
 * intialize procedure is the leftmost leaf. The node is stored at the top of
 * the stack.
 *
 * @author wjtoth
 *
 */
public class TreeHashStack {
    Stack<MerkleNode> stack;
    int maxheight;
    int leaf;

    HashFunction hashFunction;
    LeafCalc leafCalc;

    /**
     *
     * @param start
     *            leftmost leaf index of desired subtree
     * @param maxheight
     *            height of root
     * @param hashFunction
     *            the hash function the underlying merkle tree uses
     * @param leafCalc
     *            an oracle which computes leaf hash values
     */
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

    /**
     *
     * @return min height of a node in stack. Edge cases: if stack is empty
     *         returns maxheight, if algorithm as already found its target
     *         subtree root, returns "infinity" aka MAX_VALUE
     */
    public int low() {
	if (this.stack.isEmpty()) {
	    return this.maxheight;
	}
	if (this.stack.peek().getHeight() == this.maxheight) {
	    return Integer.MAX_VALUE;
	}
	int minheight = Integer.MAX_VALUE;

	// stacks stay relatively small so this is faster than maintaining
	// minheight during each push pop operation
	for (final MerkleNode merkleNode : this.stack) {
	    if (merkleNode.getHeight() < minheight) {
		minheight = merkleNode.getHeight();
	    }
	}
	return minheight;
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
