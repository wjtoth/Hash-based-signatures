package wjtoth.MSS;

import hashing.Hash;
import signatures.PrivateKey;
import signatures.PublicKey;
import signatures.Signer;
import signatures.Verifier;

/**
 * An oracle used by MerkleSS and TreeHashStack to compute leaf hashes, sign,
 * and verify at leaves
 *
 * @author wjtoth
 *
 */
public interface LeafOracle {
    /**
     *
     * @param leaf
     * @return return a Signer for signing leaves
     */
    public Signer getSigner();

    /**
     *
     * @param leaf
     * @return return SigningKey associated with leaf
     * @throws Exception
     */
    public PrivateKey getSigningKey(int leaf) throws Exception;

    /**
     *
     * @param leaf
     * @return return VerificationKey associated with leaf
     * @throws Exception
     */
    public PublicKey getVerificationKey(int leaf) throws Exception;

    /**
     *
     * @param leaf
     * @return return a Verifier for verifying signatures of leaves
     */
    public Verifier getVerifier();

    /**
     *
     * @param leaf
     * @return return Hash associated with leaf
     * @throws Exception
     */
    public Hash leafCalc(int leaf) throws Exception;

    /**
     * This method resets the LeafOracle choice of signing/verifying keys
     *
     * @param numberOfLeaves
     * @return a LeafOracle for trees using this number of leaves
     */
    public LeafOracle setNumberOfLeaves(int numberOfLeaves);
}
