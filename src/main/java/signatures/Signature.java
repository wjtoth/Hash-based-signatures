package signatures;

public abstract class Signature {
    Object material;

    public Signature(Object material) {
	this.material = material;
    }

    public Object getMaterial() {
	return this.material;
    }
}
