package wjtoth.MSS;

import hashing.HashFunction;
import hashing.HashFunctionSha512;
import junit.framework.Assert;
import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import ots.KeyGeneratorLamport;
import ots.SignerLamport;
import ots.VerifierLamport;
import signatures.KeyGenerator;
import signatures.PublicKey;
import signatures.Signature;
import signatures.SignatureScheme;
import signatures.Signer;
import signatures.Verifier;

public class MerkleClassicalTest extends TestCase {
    public static Test suite() {
	return new TestSuite(MerkleClassicalTest.class);
    }

    /**
     * Create the test case
     *
     * @param testName
     *            name of the test case
     */
    public MerkleClassicalTest(String testName) {
	super(testName);
    }

    public void testMerkleClassical() throws Exception {
	final HashFunction hashFunction = new HashFunctionSha512();
	final KeyGenerator keyGenerator = new KeyGeneratorLamport(hashFunction, hashFunction.getBitLength());
	final Signer signer = new SignerLamport(hashFunction.getBitLength());
	final Verifier verifier = new VerifierLamport(hashFunction, hashFunction.getBitLength());
	final SignatureScheme signatureScheme = new SignatureScheme(keyGenerator, signer, verifier);

	final int HEIGHT = 10;
	final MerkleSS merkleSS = new MerkleSSClassical(hashFunction, signatureScheme, HEIGHT);
	final PublicKey publicKey = merkleSS.generatePublicKey();
	for (int i = 0; i < (int) Math.pow(2, HEIGHT); ++i) {

	    final Signature signature = merkleSS.sign("HelloWorld");

	    final VerifierMerkle verifierMerkle = new VerifierMerkle(hashFunction, verifier);

	    Assert.assertTrue(verifierMerkle.verify("HelloWorld", signature, publicKey));
	    Assert.assertFalse(verifierMerkle.verify("HelloNewWorld", signature, publicKey));
	}
    }
}
