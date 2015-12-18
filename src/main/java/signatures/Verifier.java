package signatures;

/**
 * Verifies a message signed with a Signer to be authentic
 *
 * @author wjtoth
 *
 */
public interface Verifier {
    public boolean verify(String message, Signature signature, PublicKey publicKey) throws Exception;
}
