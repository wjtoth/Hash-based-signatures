package ots;

import org.apache.commons.lang3.ArrayUtils;

import hashing.Hash;
import signatures.PublicKey;

/**
 * Lamport Verification Key structure. Consists of two arrays of hashes. Please
 * note that Keys should only be used with a single message.
 * 
 * @author wjtoth
 *
 */
public class PublicKeyLamport implements PublicKey {
    Hash[] y1;
    Hash[] y2;

    public PublicKeyLamport(Hash[] y1, Hash[] y2) {
	this.y1 = y1;
	this.y2 = y2;
    }

    public Hash[] getY1() {
	return this.y1;
    }

    // TODO bounds check
    public Hash getY1(int i) {
	return this.y1[i];
    }

    public Hash[] getY2() {
	return this.y2;
    }

    // TODO bounds check
    public Hash getY2(int i) {
	return this.y2[i];
    }

    @Override
    public byte[] toByteArray() {
	byte[] data = this.y1[0].getData();
	for (int i = 1; i < this.y1.length; ++i) {
	    data = ArrayUtils.addAll(data, this.y1[i].getData());
	}
	for (final Hash element : this.y2) {
	    data = ArrayUtils.addAll(data, element.getData());
	}
	return data;
    }
}
