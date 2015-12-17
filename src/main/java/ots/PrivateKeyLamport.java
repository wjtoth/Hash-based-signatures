package ots;

import java.math.BigInteger;

import org.apache.commons.lang3.ArrayUtils;

import signatures.PrivateKey;

/**
 * Please note that keys are only intended to be used once
 **/
public class PrivateKeyLamport implements PrivateKey {

    private final BigInteger[] x1;
    private final BigInteger[] x2;

    public PrivateKeyLamport(BigInteger[] x1, BigInteger[] x2) {
	this.x1 = x1;
	this.x2 = x2;
    }

    public BigInteger[] getX1() {
	return this.x1;
    }

    // TODO bounds check
    public BigInteger getX1(int i) {
	return this.x1[i];
    }

    public BigInteger[] getX2() {
	return this.x2;
    }

    // TODO bounds check
    public BigInteger getX2(int i) {
	return this.x2[i];
    }

    @Override
    public byte[] toByteArray() {
	byte[] data = this.x1[0].toByteArray();
	for (int i = 1; i < this.x1.length; ++i) {
	    data = ArrayUtils.addAll(data, this.x1[i].toByteArray());
	}
	for (final BigInteger element : this.x2) {
	    data = ArrayUtils.addAll(data, element.toByteArray());
	}
	return data;
    }
}
