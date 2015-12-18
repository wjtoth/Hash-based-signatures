package signatures;

import hashing.Hashable;

/**
 * Signatures are the output of a Signer. They are used to authenticate
 * messages. They need to be Hashable for used in Merkle Trees.
 * 
 * @author wjtoth
 *
 */
public interface Signature extends Hashable {
}
