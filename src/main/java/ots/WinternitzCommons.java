package ots;

import java.math.BigInteger;
import java.util.BitSet;

import org.apache.commons.lang3.ArrayUtils;

import hashing.Hash;
import hashing.HashFunction;
import wjtoth.MSS.IntMath;

/**
 * Common functions elements of the Winternitz signature scheme need to perform.
 *
 * @author wjtoth
 *
 */
public class WinternitzCommons {
    /**
     * Interprets each binary block as an integer and sums them each with 2^w to
     * obtain a checksum integer
     *
     * @param b
     *            blocks of binary
     * @param w
     *            the Winternitz parameter
     * @return checksum integer
     */
    public static BigInteger computeCheckSum(BitSet[] b, int w) {
	BigInteger c = BigInteger.ZERO;
	final long twoW = IntMath.binpower((long) w);
	final BigInteger twoWBI = BigInteger.valueOf(twoW);
	ArrayUtils.toString(b);
	for (final BitSet element : b) {
	    // b may not be full when this is called
	    if (element == null) {
		break;
	    }
	    c = c.add(twoWBI);
	    if (element.length() > 0) {
		final BigInteger bBI = new BigInteger(element.toByteArray());
		c = c.add(bBI);
	    }
	}
	return c;
    }

    /**
     *
     * @param k
     *            bitlength of hash function output
     * @param w
     *            Winternitz parameter
     * @param kwratio
     *            ceiling of k/w
     * @return parameter t as described in reference literature on Winternitz
     *         one time signatures
     */
    public static int computeT(int k, int w, int kwratio) {
	final double log = IntMath.binlog(kwratio);
	final double sum = Math.floor(log) + 1 + w;
	return kwratio + (int) Math.ceil(sum / w);
    }

    /**
     *
     * @param y
     *            an array of hashes to be concatentated
     * @param h
     *            hash function to use on concatentation
     * @return hash of all y concatenated together
     */
    public static Hash concatAllAndHash(Hash[] y, HashFunction h) {
	final Hash hash = y[0];
	for (int i = 1; i < y.length; ++i) {
	    hash.concat(y[i]);
	}
	return h.hash(hash);
    }

    /**
     *
     * @param x
     *            initial integer to hash (interpreted as byte[])
     * @param h
     *            hash function to use
     * @param power
     *            number of times hash x
     * @return x hashed power times using h
     * @throws Exception
     */
    public static Hash powerhash(BigInteger x, HashFunction h, int power) throws Exception {
	if (power == 0) {
	    return new Hash(x.toByteArray());
	}
	Hash hash = h.hash(x.toByteArray());
	for (int i = 1; i < power; ++i) {
	    hash = h.hash(hash);
	}
	return hash;
    }

    /**
     *
     * @param hash
     *            initial hash data to hash (interpreted as byte[])
     * @param h
     *            hash function to use
     * @param power
     *            number of times hash data
     * @return data hashed power times using h
     * @throws Exception
     */
    public static Hash powerhash(Hash hash, HashFunction h, int power) throws Exception {
	Hash returnHash = h.hash(hash);
	for (int i = 0; i < power; ++i) {
	    returnHash = h.hash(returnHash);
	}
	return returnHash;
    }

}
