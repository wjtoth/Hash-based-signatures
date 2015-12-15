package hashing;

public class HashFunctionSha512 implements HashFunction {
    public final int bitLength = 512;

    @Override
    public int getBitLength() {
	return 512;
    }

    @Override
    public Hash hash(String message) {
	return new Hash(org.apache.commons.codec.digest.DigestUtils.sha512(message));
    }
}