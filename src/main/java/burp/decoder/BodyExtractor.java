package burp.decoder;

public interface BodyExtractor {
	public byte[] extractRequestBody(byte[] message);
	public byte[] extractResponseBody(byte[] message);
}
