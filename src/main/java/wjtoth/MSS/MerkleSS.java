package wjtoth.MSS;

import java.util.ArrayList;
import java.util.Stack;

import hashing.Hash;
import hashing.HashFunction;
import signatures.PublicKey;
import signatures.Signature;

/**
 * Abstract class for Merkle Signature Scheme implementations. The abstract
 * method which needs implementation concerns how you wish to efficient traverse
 * the Merkle Tree
 *
 * @author wjtoth
 *
 */
public abstract class MerkleSS {

    private final HashFunction hashFunction;
    protected final int height;
    protected int leaf;
    protected final int numberOfLeaves;
    private final LeafOracle leafOracle;

    protected final ArrayList<TreeHashStack> stacks;

    protected final Hash[] auth;

    /**
     *
     * @param hashFunction
     *            a collision resistant hash function
     * @param signatureScheme
     *            a one time signature scheme
     * @param height
     *            the height of the merkle tree. 2^height messages can be signed
     *            with this scheme.
     */
    public MerkleSS(HashFunction hashFunction, LeafOracle leafOracle, int height) {
	this.hashFunction = hashFunction;
	this.height = height;
	this.leaf = 0;
	this.numberOfLeaves = IntMath.binpower(height);
	this.leafOracle = leafOracle.setNumberOfLeaves(this.numberOfLeaves);
	this.stacks = new ArrayList<TreeHashStack>(this.height);
	for (int i = 0; i < height; ++i) {
	    this.stacks.add(new TreeHashStack(0, i, hashFunction, this.leafOracle));
	}
	this.auth = new Hash[height];
    }

    /**
     *
     * @return PublicKey consisting of the hash value at the tree root.
     * @throws Exception
     */
    public PublicKey generatePublicKey() throws Exception {
	// A total treehash, no need to used incremental data structure since
	// we're going straight to the root in one shot
	final Stack<MerkleNode> stack = new Stack<MerkleNode>();
	int maxHeightReached = -1;
	for (int j = 0; j < this.numberOfLeaves; ++j) {
	    MerkleNode node1 = new MerkleNode(this.leafOracle.leafCalc(j), 0);
	    while (!stack.empty() && (stack.peek().getHeight() == node1.getHeight())) {
		final MerkleNode node2 = stack.pop();
		final int h = node1.getHeight();
		// record initial values for auth and stack tops when we find
		// them
		if (h > maxHeightReached) {
		    this.stacks.get(h).initialize(IntMath.binpower(h), h).push(node2);
		    this.auth[h] = node1.getHash();
		    ++maxHeightReached;
		}
		node1 = new MerkleNode(this.hashFunction.hash(node2.getHash().concat(node1.getHash())), h + 1);
	    }
	    stack.push(node1);
	}
	final Hash root = stack.pop().getHash();
	return new PublicKeyMerkle(root);
    }

    /**
     *
     * @return a VerifierMerkle to be used with signatures from this tree
     */
    public VerifierMerkle getVerifier() {
	return new VerifierMerkle(this.hashFunction, this.leafOracle.getVerifier());
    }

    /**
     *
     * @param message
     *            String value of message to be signed
     * @return returns a SignatureMerkle (see class for structure)
     * @throws Exception
     *             can only sign 2^height messages, if called after signing so
     *             many will throw exception
     */
    public Signature sign(String message) throws Exception {
	if (this.leaf >= this.numberOfLeaves) {
	    throw new Exception("out of signing leaves");
	}
	final Signature sig1 = this.leafOracle.getSigner().sign(message, this.leafOracle.getSigningKey(this.leaf));
	// copies auth path hashes since they will be changed before returning
	// signature
	final Hash[] a = new Hash[this.height];
	for (int i = 0; i < this.height; ++i) {
	    a[i] = new Hash(this.auth[i].getData());
	}
	final Signature sig = new SignatureMerkle(sig1, this.leafOracle.getVerificationKey(this.leaf), a, this.leaf);

	// calling traverseTree after running out of leaves may cause
	// IndexOutOfBoundsException so best to not do that
	if (this.leaf < (this.numberOfLeaves - 1)) {
	    this.traverseTree();
	} else {
	    ++this.leaf;
	}

	return sig;
    }

    /**
     * traverseTree precomputes the next auth path which will be needed for
     * signing
     * 
     * @throws Exception
     */
    protected abstract void traverseTree() throws Exception;
}