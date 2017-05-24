package be.msec.client.connection;

public class CardConnectException extends Exception {
	
	private String message;
	
	public CardConnectException(String msg) {
		this.message = msg;
	}
	
	@Override
	public String getMessage() {
		return this.message;
	}
}
