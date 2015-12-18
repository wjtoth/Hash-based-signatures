package hashing;

/**
 * A specific implementation of HashFunction using the common Sha512 algorithm
 * 
 * @author wjtoth
 *
 */
public class HashFunctionSha512 extends HashFunction {
    public final int bitLength = 512;

    @Override
    public int getBitLength() {
	return 512;
    }

    @Override
    public Hash hash(byte[] data) {
	return new Hash(org.apache.commons.codec.digest.DigestUtils.sha512(data));
    }

}