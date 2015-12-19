package wjtoth.MSS;

import java.math.BigInteger;

import hashing.Hash;
import hashing.HashFunction;
import hashing.HashFunctionSha512;
import ots.KeyGeneratorLamport;
import ots.KeyGeneratorWinternitz;
import ots.SignerLamport;
import ots.SignerWinternitz;
import ots.VerifierLamport;
import ots.VerifierWinternitz;
import signatures.KeyGenerator;
import signatures.PublicKey;
import signatures.Signature;
import signatures.SignatureScheme;
import signatures.Signer;
import signatures.Verifier;

/**
 * Main method. Some quick tests appear here.
 */
public class App {

    public static void main(String[] args) throws Exception {
	System.out.println("Some Performance Tests on trees of height 12 using Sha512 for Hashing (times in ms):");
	final int height = 12;
	System.out.println("Using Winternitz Signatures with parameter w = 2:");
	final int w = 2;
	final HashFunction hashFunction = new HashFunctionSha512();
	final int messageBitLength = hashFunction.getBitLength();
	final KeyGenerator keyGenerator = new KeyGeneratorWinternitz(hashFunction, messageBitLength, w);
	final Signer signer = new SignerWinternitz(hashFunction, messageBitLength, w);
	final Verifier verifier = new VerifierWinternitz(hashFunction, messageBitLength, w);
	final SignatureScheme signatureScheme = new SignatureScheme(keyGenerator, signer, verifier);
	final LeafOracle leafOracle = new LeafOracleOTS(hashFunction, signatureScheme);
	System.out.println("\nThe Classical Tree Traversal");
	App.testTree(hashFunction, leafOracle, new MerkleSSClassical(hashFunction, leafOracle, height));
	System.out.println("\nThe Classical Tree Traversal in Parallel");
	App.testTree(hashFunction, leafOracle, new MerkleSSParallel(hashFunction, leafOracle, height));
	System.out.println("\nThe Logarithmic Tree Traversal");
	App.testTree(hashFunction, leafOracle, new MerkleSSLogarithmic(hashFunction, leafOracle, height));

	System.out.println("\nThe Classical Tree Traversal using Lamport Signatures");
	final KeyGenerator keyGeneratorL = new KeyGeneratorLamport(hashFunction, messageBitLength);
	final Signer signerL = new SignerLamport(messageBitLength);
	final Verifier verifierL = new VerifierLamport(hashFunction, messageBitLength);
	final SignatureScheme signatureSchemeL = new SignatureScheme(keyGeneratorL, signerL, verifierL);
	final LeafOracle leafOracleL = new LeafOracleOTS(hashFunction, signatureSchemeL);
	App.testTree(hashFunction, leafOracleL, new MerkleSSClassical(hashFunction, leafOracleL, height));
    }

    private static void testTree(HashFunction hashFunction, LeafOracle leafOracle, MerkleSS merkleSS) throws Exception {
	System.out.println("Time to compute root");
	long start = System.currentTimeMillis();
	final PublicKey publicKey = merkleSS.generatePublicKey();
	long finish = System.currentTimeMillis();
	System.out.println(finish - start);
	System.out.println("Time to sign a message (given message 'Hello')");
	final String message = "Hello";
	start = System.currentTimeMillis();
	final Signature signature = merkleSS.sign(message);
	finish = System.currentTimeMillis();
	System.out.println(finish - start);
	System.out.println("Time to verify the message as authentic");
	final VerifierMerkle verifierMerkle = new VerifierMerkle(hashFunction, leafOracle.getVerifier());
	start = System.currentTimeMillis();
	boolean isAuthentic = verifierMerkle.verify(message, signature, publicKey);
	finish = System.currentTimeMillis();
	System.out.println(finish - start);
	System.out.println("message found to be real: " + isAuthentic);
	System.out.println("Attempting to verify a different message ('Bye') with the same signature");
	isAuthentic = verifierMerkle.verify("Bye", signature, publicKey);
	System.out.println("message found to be real: " + isAuthentic);
	System.out.println("Attempting to verify original message ('Hello') with a different Public Key");
	// odds of this colliding are astronomically low
	final PublicKey badPublicKey = new PublicKeyMerkle(new Hash(BigInteger.TEN.toByteArray()));
	isAuthentic = verifierMerkle.verify(message, signature, badPublicKey);
	System.out.println("message found to be real: " + isAuthentic);
    }
}
