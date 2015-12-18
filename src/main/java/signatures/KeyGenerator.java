package signatures;

/**
 * Outputs a KeyPair to be used in signing and verifying digital signatures.
 * 
 * @author wjtoth
 *
 */
public interface KeyGenerator {
    KeyPair generateKeys() throws Exception;
}
