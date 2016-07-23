package burp.decoder;

public class ProtoDefinitionFaultyException extends Exception {

	private static final long serialVersionUID = 5905169456828571575L;

	public ProtoDefinitionFaultyException() {
		super();
	}

	public ProtoDefinitionFaultyException(String message, Throwable cause, boolean enableSuppression,
			boolean writableStackTrace) {
		super(message, cause, enableSuppression, writableStackTrace);
	}

	public ProtoDefinitionFaultyException(String message, Throwable cause) {
		super(message, cause);
	}

	public ProtoDefinitionFaultyException(String message) {
		super(message);
	}

	public ProtoDefinitionFaultyException(Throwable cause) {
		super(cause);
	}

}
