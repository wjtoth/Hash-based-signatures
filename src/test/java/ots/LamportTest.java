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

public class LamportTest extends TestCase {
    public static Test suite() {
	return new TestSuite(LamportTest.class);
    }

    /**
     * Create the test case
     *
     * @param testName
     *            name of the test case
     */
    public LamportTest(String testName) {
	super(testName);
    }

    public void testLamport() throws Exception {
	final HashFunction hashFunction = new HashFunctionSha512();
	final KeyGenerator keyGenerator = new KeyGeneratorLamport(hashFunction, hashFunction.getBitLength());
	final KeyPair keyPair = keyGenerator.generateKeys();
	final Signer signer = new SignerLamport(hashFunction.getBitLength());
	final Signature signature = signer.sign("HelloWorld", keyPair.getPrivateKey());
	final Verifier verifier = new VerifierLamport(hashFunction, hashFunction.getBitLength());
	Assert.assertTrue(verifier.verify("HelloWorld", signature, keyPair.getPublicKey()));
	Assert.assertFalse(verifier.verify("HelloNewWorld", signature, keyPair.getPublicKey()));
    }
}
