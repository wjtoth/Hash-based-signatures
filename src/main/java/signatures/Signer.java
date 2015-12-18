package signatures;

/**
 * Signs messages to be authenticated with a Verifier
 * 
 * @author wjtoth
 *
 */
public interface Signer {
    public Signature sign(String message, PrivateKey privateKey) throws Exception;
}
