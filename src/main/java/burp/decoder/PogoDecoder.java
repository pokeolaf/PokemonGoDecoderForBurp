package burp.decoder;

import javax.management.RuntimeErrorException;

import burp.decoder.Decoder.IRequestDecoder;

public class PogoDecoder {

	private final BodyExtractor bodyExtractor;

	public PogoDecoder(BodyExtractor bodyExtractor) {
		super();
		this.bodyExtractor = bodyExtractor;
	}

	private Description requestDescription = new Description.STRING("nothing to parse");
	private Description responseDescription = new Description.STRING("nothing to parse");

	public void decode(byte[] request, byte[] response) {
		if (request == null || request.length == 0) {
			return;
		}
		try {
			request = bodyExtractor.extractRequestBody(request);
		} catch (NullPointerException e) {
			throw new RuntimeException("extracting");
		}
		IRequestDecoder requestDecoder = null;
		try {
			requestDecoder = Decoder.DecoderFactory.newBuilder().putRequest(request).build();
		} catch (NullPointerException e) {
			throw new RuntimeException("building decoder");
		}
		try {
			requestDescription = requestDecoder.decode();
		} catch (NullPointerException e) {
			throw new RuntimeException("decode ");
		}

		if (response != null && response.length != 0) {
			response = bodyExtractor.extractResponseBody(response);
			this.responseDescription = Decoder.DecoderFactory.newBuilder().putResponse(response)
					.putResponseDecoderHints(requestDecoder.getResponseDecoderHints()).build().decode();
		}
	}

	public Description getRequestDescription() {
		return requestDescription;
	}

	public Description getResponseDescription() {
		return responseDescription;
	}

}
