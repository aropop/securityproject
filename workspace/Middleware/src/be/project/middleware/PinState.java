package be.project.middleware;

public class PinState {
	
	public final static int WAITING = 1;
	public final static int PIN_DONE = 2;
	public final static int ATTRIBUTES_READY = 3;
	public final static int ERROR = 5;
	
	private int status;
	private byte[] attributes;
	
	
	public PinState() {
		this.status = WAITING;
	}
	
	public int status() {
		return status;
	}
	
	public void setStatus(int s) {
		this.status = s;
	}
	
	public void setData(byte[] d) {
		this.attributes = d;
	}
	
	public byte[] attributes() {
		return attributes;
	}

}
