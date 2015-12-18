package signatures;

import hashing.Hashable;

/**
 * Keys (of which there are public and private variations) need to be hashable
 * for compatibility with Merkle Trees
 * 
 * @author wjtoth
 *
 */
public interface Key extends Hashable {
}
