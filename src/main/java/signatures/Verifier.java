package signatures;

public interface Verifier {
    public boolean verify(String message, Signature signature, PublicKey publicKey) throws Exception;
}
