package burp.decoder;

import java.util.Arrays;

import burp.IExtensionHelpers;
import pokeolaf.decoder.BodyExtractor;

public class BurpBodyExtractor implements BodyExtractor {

	private final IExtensionHelpers helpers;

	public BurpBodyExtractor(IExtensionHelpers helpers) {
		super();
		this.helpers = helpers;
	}

	@Override
	public byte[] extractRequestBody(byte[] message) {
		int bodyStart = helpers.analyzeRequest(message).getBodyOffset();
		return copyTill(message, bodyStart);
	}

	@Override
	public byte[] extractResponseBody(byte[] message) {
		int bodyStart = helpers.analyzeResponse(message).getBodyOffset();
		return copyTill(message, bodyStart);
	}

	private byte[] copyTill(byte[] message, int bodyStart) {
		return Arrays.copyOfRange(message, bodyStart, message.length);
	}

}
