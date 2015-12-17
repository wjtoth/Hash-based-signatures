package ots;

import java.math.BigInteger;

import org.apache.commons.lang3.ArrayUtils;

import signatures.Signature;

public class SignatureLamport implements Signature {

    private final BigInteger[] sig;

    public SignatureLamport(BigInteger[] sig) {
	this.sig = sig;
    }

    public BigInteger[] getSig() {
	return this.sig;
    }

    public BigInteger getSig(int i) {
	return this.sig[i];
    }

    @Override
    public byte[] toByteArray() {
	byte[] data = this.sig[0].toByteArray();
	for (int i = 1; i < this.sig.length; ++i) {
	    data = ArrayUtils.addAll(data, this.sig[i].toByteArray());
	}
	return data;
    }

}
