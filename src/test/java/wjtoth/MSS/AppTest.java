package wjtoth.MSS;

import java.util.BitSet;

import junit.framework.Assert;
import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

/**
 * Unit test for simple App.
 */
public class AppTest extends TestCase {
    /**
     * @return the suite of tests being tested
     */
    public static Test suite() {
	return new TestSuite(AppTest.class);
    }

    /**
     * Create the test case
     *
     * @param testName
     *            name of the test case
     */
    public AppTest(String testName) {
	super(testName);
    }

    /**
     * Rigourous Test :-)
     */
    public void testApp() {
	Assert.assertTrue(true);
	final BitSet bitSet = new BitSet(512);
	System.out.println(bitSet.length());
	System.out.println(bitSet.size());
	final BitSet word = BitSet.valueOf("helloworld".getBytes());
	System.out.println(word.length());
	System.out.println(word.size());
	bitSet.or(word);
	System.out.println(bitSet.length());
	System.out.println(bitSet.size());
	System.out.println(new String(bitSet.toByteArray()));
    }
}
