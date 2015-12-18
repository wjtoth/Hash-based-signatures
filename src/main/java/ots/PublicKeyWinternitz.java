package ots;

import hashing.Hash;
import signatures.PublicKey;

/**
 * Winternitz Verification Key structure. Consists of a single Hash. Please note
 * that keys should only be used once.
 * 
 * @author wjtoth
 *
 */
public class PublicKeyWinternitz implements PublicKey {

    private final Hash y;

    public PublicKeyWinternitz(Hash y) {
	this.y = y;
    }

    public Hash getY() {
	return this.y;
    }

    @Override
    public byte[] toByteArray() {
	return this.y.getData();
    }

}
