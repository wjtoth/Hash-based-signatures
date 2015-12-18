package wjtoth.MSS;

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
	final int i = 1;
	for (int h = 0; h < 4; ++h) {
	    System.out.println(i << h);
	}
    }
}
