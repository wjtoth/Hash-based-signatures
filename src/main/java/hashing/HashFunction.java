package hashing;

/**
 * HashFunctions take data and map it to fixed bit length binary strings. An
 * implementation should be collision resistant for out purposes.
 *
 * @author wjtoth
 *
 */
public abstract class HashFunction {
    /**
     *
     * @return number of bits in function output
     */
    public abstract int getBitLength();

    public abstract Hash hash(byte[] data);

    public final Hash hash(Hashable message) {
	return this.hash(message.toByteArray());
    }

    public final Hash hash(String message) {
	return this.hash(message.getBytes());
    }

}
