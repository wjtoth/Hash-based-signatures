package hashing;

import junit.framework.Assert;
import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

public class HashFunctionSha512Test extends TestCase {
    /**
     * @return the suite of tests being tested
     */
    public static Test suite() {
	return new TestSuite(HashFunctionSha512Test.class);
    }

    /**
     * Create the test case
     *
     * @param testName
     *            name of the test case
     */
    public HashFunctionSha512Test(String testName) {
	super(testName);
    }

    /**
     * Verify Hashing is operating as expected
     */
    public void testHashFunctionSha512() {
	final String message1 = "hello";
	final String message2 = "world";
	final String message = "helloworld";

	final HashFunction h = new HashFunctionSha512();

	// check concatenation
	Assert.assertTrue(h.hash(message1.concat(message2)).equals(h.hash(message)));
	Assert.assertTrue(h.hash(h.hash(message1).concat(message2)).equals(h.hash(h.hash(message1).concat(message2))));

	final HashFunction g = new HashFunctionSha512();

	// check different instances behave the same
	Assert.assertTrue(h.hash(message).equals(g.hash(message)));

	// check that different hashes are not considered equal
	Assert.assertFalse(h.hash(message1).equals(h.hash(message2)));
    }
}
