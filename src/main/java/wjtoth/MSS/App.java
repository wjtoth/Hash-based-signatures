package wjtoth.MSS;

import java.util.BitSet;

import hashing.HashFunction;
import hashing.HashFunctionSha512;
import ots.KeyGeneratorWinternitz;
import ots.SignerWinternitz;
import ots.VerifierWinternitz;
import signatures.KeyGenerator;
import signatures.PublicKey;
import signatures.Signature;
import signatures.SignatureScheme;
import signatures.Signer;
import signatures.Verifier;

/**
 * Main method. A quick story about Digital Signatures
 */
public class App {

    public static void main(String[] args) throws Exception {
	System.out.println("Merkle Tree Signing Demonstration:");
	System.out.println("Suppose we have two friends Alice and Bob.");
	System.out.println("Suppose we also have Eve who is jealous of Alice's friendship Bob.");
	System.out.println("Eve is known for trying to impersonate Alice to talk to Bob.");
	System.out
		.println("It's beginning to be a problem for Alice and Bob who have very important messages to share.");
	System.out.println(
		"So Alice and Bob decide to use Digital Signatures to verify each other's identity while speaking.");
	System.out.println(
		"But they cannot chose any old Digital Signature Scheme, since they're afraid Eve has a Quantum Computer!");
	System.out
		.println("So they agree to use the Merkle Tree Signature Scheme with Winternitz One Time Signatures.");

	System.out.println("\nAlice wants to send Bob a message. So Alice sets up her Merkle Tree.");
	System.out
		.println("They've already agreed leaves will be signed with Winternitz signatures with parameter w=2");
	System.out.println("they've also decided to use Sha512 for hashing");

	final HashFunction hashFunction = new HashFunctionSha512();
	final int bitLength = 512;
	final int w = 2;
	final KeyGenerator keyGenerator = new KeyGeneratorWinternitz(hashFunction, bitLength, w);
	final Signer signer = new SignerWinternitz(hashFunction, hashFunction.getBitLength(), w);
	final Verifier verifier = new VerifierWinternitz(hashFunction, hashFunction.getBitLength(), w);
	final SignatureScheme signatureScheme = new SignatureScheme(keyGenerator, signer, verifier);

	final int height = 4;
	final MerkleSS aliceMerkleSS = new MerkleSSClassical(hashFunction, signatureScheme, height);

	System.out.println("Alice then computes her public key and sends it to Bob");
	final PublicKey publicKey = aliceMerkleSS.generatePublicKey();
	System.out.println("Alice's Public Key: ");
	App.printBits(publicKey.toByteArray());

	System.out.println("Now Alice wants to send Bob the message 'I think you are great'.");
	System.out.println("She signs the message with her Merkle Signature Scheme");
	final String message = "I think you are great";
	final Signature signature = aliceMerkleSS.sign(message);
	System.out.println("Alice's message Signature:");
	App.printBits(signature.toByteArray());

	System.out.println("Alice gives her message and signature to Bob");
	System.out.println("Bob constructs his Verifier for messages from Alice.");
	final Verifier bobVerifier = new VerifierMerkle(hashFunction, verifier);
	System.out.println("Bob uses the Verifier with Alice's public key to check that the message came from Alice.");
	System.out.println("Verifier response:");
	System.out.println(bobVerifier.verify(message, signature, publicKey));
	System.out.println("Bob smiles :)");

	System.out.println(
		"Eve wants to ruin Bob's friendship with Alice so she attempts to impersonate Alice and give Bob the message 'I DONT think you are great'.");
	final String messageEve = "I DONT think you are great";
	System.out.println("Eve doesn't know how to compute the signature though.");
	System.out.println("Her quantum computer is useless, there is no factoring or discrete logarithms involved.");
	System.out.println("She tries to use a previous signature she found Alice give Bob");

	System.out.println("Bob uses the Verifier with Alice's public key to check that the message came from Alice.");
	System.out.println("Verifier response:");
	System.out.println(bobVerifier.verify(messageEve, signature, publicKey));
	System.out.println("Bob is glad Alice wouldn't say something so mean. Bob smiles :)");
    }

    private static void printBits(byte[] data) {
	final BitSet bitSet = BitSet.valueOf(data);
	for (int i = 0; i < bitSet.size(); ++i) {
	    if (bitSet.get(i)) {
		System.out.print(1);
	    } else {
		System.out.print(0);
	    }
	}
	System.out.println();
    }
}
