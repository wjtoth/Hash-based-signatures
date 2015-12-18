package wjtoth.MSS;

import hashing.Hash;

/**
 * An oracle used by TreeHashStack to compute leaf hashes
 *
 * @author wjtoth
 *
 */
public interface LeafCalc {
    public Hash computeLeaf(int leaf);
}
