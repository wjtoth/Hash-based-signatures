package signatures;

public interface Signer {
    public Signature sign(String message, PrivateKey signingKey);
}
