package hashing;

public interface HashFunction {
    public int getBitLength();

    public Hash hash(String message);
}
