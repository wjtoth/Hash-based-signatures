package ots;

import hashing.HashFunction;
import hashing.HashFunctionSha512;
import junit.framework.Assert;
import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import signatures.KeyGenerator;
import signatures.KeyPair;
import signatures.Signature;
import signatures.Signer;
import signatures.Verifier;

public class WinternitzTest extends TestCase {
    public static Test suite() {
	return new TestSuite(WinternitzTest.class);
    }

    /**
     * Create the test case
     *
     * @param testName
     *            name of the test case
     */
    public WinternitzTest(String testName) {
	super(testName);
    }

    public void testWinternitz() throws Exception {
	final HashFunction hashFunction = new HashFunctionSha512();
	final int w = 2;
	final KeyGenerator keyGenerator = new KeyGeneratorWinternitz(hashFunction, hashFunction.getBitLength(), w);
	final KeyPair keyPair = keyGenerator.generateKeys();
	final Signer signer = new SignerWinternitz(hashFunction, hashFunction.getBitLength(), w);
	final Signature signature = signer.sign("HelloWorld", keyPair.getPrivateKey());
	final Verifier verifier = new VerifierWinternitz(hashFunction, hashFunction.getBitLength(), w);
	Assert.assertTrue(verifier.verify("HelloWorld", signature, keyPair.getPublicKey()));
	Assert.assertFalse(verifier.verify("HelloNewWorld", signature, keyPair.getPublicKey()));
    }
}
