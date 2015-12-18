package wjtoth.MSS;

import java.util.ArrayList;
import java.util.Stack;

import hashing.Hash;
import hashing.HashFunction;
import signatures.KeyPair;
import signatures.PrivateKey;
import signatures.PublicKey;
import signatures.Signature;
import signatures.SignatureScheme;

/**
 * Abstract class for Merkle Signature Scheme implementations. The abstract
 * method which needs implementation concerns how you wish to efficient traverse
 * the Merkle Tree
 *
 * @author wjtoth
 *
 */
public abstract class MerkleSS {

    /**
     * Use the appropriately indexed verification key to give a leaf hash value.
     * The tree traversal will take this as its oracle.
     *
     * @author wjtoth
     *
     */
    private class LeafOracle implements LeafCalc {

	@Override
	public Hash computeLeaf(int leaf) {
	    return MerkleSS.this.hashFunction.hash(MerkleSS.this.verificationKeys[leaf]);
	}

    }

    private final HashFunction hashFunction;
    private final SignatureScheme signatureScheme;
    protected final int height;
    protected int leaf;
    protected final int numberOfLeaves;

    protected final ArrayList<TreeHashStack> stacks;

    protected final Hash[] auth;
    // TODO figure out how to do this "online"
    // should become clear once things are put together
    private final PrivateKey[] signingKeys;

    private final PublicKey[] verificationKeys;

    private final LeafOracle leafOracle;

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
    public MerkleSS(HashFunction hashFunction, SignatureScheme signatureScheme, int height) {
	this.hashFunction = hashFunction;
	this.signatureScheme = signatureScheme;
	this.height = height;
	this.leaf = 0;
	this.numberOfLeaves = IntMath.binpower(height);
	this.stacks = new ArrayList<TreeHashStack>(this.height);
	this.leafOracle = new LeafOracle();
	for (int i = 0; i < height; ++i) {
	    this.stacks.add(new TreeHashStack(0, i, hashFunction, this.leafOracle));
	}
	this.auth = new Hash[height];
	this.signingKeys = new PrivateKey[this.numberOfLeaves];
	this.verificationKeys = new PublicKey[this.numberOfLeaves];
    }

    /**
     *
     * @return PublicKey consisting of the hash value at the tree root.
     * @throws Exception
     */
    public PublicKey generatePublicKey() throws Exception {
	// OTS keys need to be initialized
	for (int i = 0; i < this.numberOfLeaves; ++i) {
	    final KeyPair keyPair = this.signatureScheme.generateKeys();
	    this.signingKeys[i] = keyPair.getPrivateKey();
	    this.verificationKeys[i] = keyPair.getPublicKey();
	}

	// A total treehash, no need to used incremental data structure since
	// we're going straight to the root in one shot
	final Stack<MerkleNode> stack = new Stack<MerkleNode>();
	int maxHeightReached = -1;
	for (int j = 0; j < this.numberOfLeaves; ++j) {
	    MerkleNode node1 = new MerkleNode(this.leafOracle.computeLeaf(j), 0);
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
	final Signature sig1 = this.signatureScheme.sign(message, this.signingKeys[this.leaf]);
	// copies auth path hashes since they will be changed before returning
	// signature
	final Hash[] a = new Hash[this.height];
	for (int i = 0; i < this.height; ++i) {
	    a[i] = new Hash(this.auth[i].getData());
	}
	final Signature sig = new SignatureMerkle(sig1, this.verificationKeys[this.leaf], a, this.leaf);

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
     */
    protected abstract void traverseTree();
}