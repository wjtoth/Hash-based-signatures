package signatures;

public abstract class Key {
    Object material;
    boolean isUsed;

    public Key(Object material) {
	this.isUsed = false;
	this.material = material;
    }

    public Object getMaterial() {
	this.isUsed = true;
	return this.material;
    }

    public boolean isUsed() {
	return this.isUsed;
    }
}
