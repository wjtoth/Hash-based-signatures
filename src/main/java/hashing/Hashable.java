package hashing;

/**
 * HashFunctions are meant to operate on streams of bits. For our purposes
 * anything that can behave like such is Hashable by a HashFunction
 *
 * @author wjtoth
 *
 */
public interface Hashable {
    public byte[] toByteArray();
}
