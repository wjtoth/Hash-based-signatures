package hashing;

import org.apache.commons.lang3.ArrayUtils;

public class Hash implements Hashable {
    private final byte[] data;

    public Hash(byte[] data) {
	this.data = data;
    }

    public byte[] concat(byte[] data) {
	return ArrayUtils.addAll(this.data, data);
    }

    public Hash concat(Hash hash) {
	return new Hash(ArrayUtils.addAll(this.data, hash.getData()));
    }

    public String concat(String string) {
	return new String(this.data).concat(string);
    }

    public boolean equals(Hash hash) {
	return java.util.Objects.deepEquals(this.data, hash.getData());
    }

    public byte[] getData() {
	return this.data;
    }

    @Override
    public byte[] toByteArray() {
	return this.getData();
    }
}
