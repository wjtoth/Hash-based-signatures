package wjtoth.MSS;

public class IntMath {
    public static int binlog(int bits) // returns 0 for bits=0
    {
	int log = 0;
	if ((bits & 0xffff0000) != 0) {
	    bits >>>= 16;
	    log = 16;
	}
	if (bits >= 256) {
	    bits >>>= 8;
	    log += 8;
	}
	if (bits >= 16) {
	    bits >>>= 4;
	    log += 4;
	}
	if (bits >= 4) {
	    bits >>>= 2;
	    log += 2;
	}
	return log + (bits >>> 1);
    }

    public static int binpower(int exponent) {
	return (int) IntMath.fastpower(2, exponent);
    }

    public static long binpower(long exponent) {
	return IntMath.fastpower(2, exponent);
    }

    // from wikipedia
    public static long fastpower(long base, long exponent) {
	long x = base;
	long n = exponent;
	if (n == 0) {
	    return 1;
	}

	long y = 1;
	while (n > 1) {
	    if ((n % 2) == 0) {
		x = x * x;
		n = n / 2;
	    } else {
		y = x * y;
		x = x * x;
		n = (n - 1) / 2;
	    }
	}
	return x * y;
    }
}
