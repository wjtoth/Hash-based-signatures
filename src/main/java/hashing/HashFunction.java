package hashing;

public abstract class HashFunction {
    public abstract int getBitLength();

    public abstract Hash hash(byte[] data);

    public final Hash hash(Hashable message) {
	return this.hash(message.toByteArray());
    }

    public final Hash hash(String message) {
	return this.hash(message.getBytes());
    }

}
