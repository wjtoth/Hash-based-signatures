package wjtoth.MSS;

import hashing.Hash;
import hashing.HashFunction;
import signatures.KeyPair;
import signatures.PrivateKey;
import signatures.PublicKey;
import signatures.SignatureScheme;
import signatures.Signer;
import signatures.Verifier;

/**
 * A LeafOracle implementation based on a One Time Signature scheme like Lamport
 * or Winternitz.
 *
 * @author wjtoth
 *
 */
public class LeafOracleOTS implements LeafOracle {

    private final SignatureScheme signatureScheme;

    private PrivateKey[] signingKeys;
    private PublicKey[] verificationKeys;

    private final HashFunction hashFunction;

    /**
     * Constructs a leaf oracle for trees with 1 leaf. Call setNumberOfLeaves
     * before use if you intend to use with larger trees.
     *
     * @param signatureScheme
     *            a One Time Signature Scheme
     */
    public LeafOracleOTS(HashFunction hashFunction, SignatureScheme signatureScheme) {
	this.signatureScheme = signatureScheme;
	this.signingKeys = new PrivateKey[1];
	this.verificationKeys = new PublicKey[1];
	this.hashFunction = hashFunction;
    }

    public Signer getSigner() {
	return this.signatureScheme.getSigner();
    }

    public PrivateKey getSigningKey(int leaf) throws Exception {
	if (this.signingKeys[leaf] == null) {
	    this.makeKeyPair(leaf);
	}
	return this.signingKeys[leaf];
    }

    public PublicKey getVerificationKey(int leaf) throws Exception {
	if (this.verificationKeys[leaf] == null) {
	    this.makeKeyPair(leaf);
	}
	return this.verificationKeys[leaf];
    }

    public Verifier getVerifier() {
	return this.signatureScheme.getVerifier();
    }

    public Hash leafCalc(int leaf) throws Exception {
	return this.hashFunction.hash(this.getVerificationKey(leaf));
    }

    /**
     * Store a new keyPair in position indicated by leaf
     *
     * @param leaf
     * @throws Exception
     */
    private void makeKeyPair(int leaf) throws Exception {
	final KeyPair keyPair = this.signatureScheme.generateKeys();
	this.signingKeys[leaf] = keyPair.getPrivateKey();
	this.verificationKeys[leaf] = keyPair.getPublicKey();
    }

    public LeafOracle setNumberOfLeaves(int numberOfLeaves) {
	this.signingKeys = new PrivateKey[numberOfLeaves];
	this.verificationKeys = new PublicKey[numberOfLeaves];
	return this;
    }

}
