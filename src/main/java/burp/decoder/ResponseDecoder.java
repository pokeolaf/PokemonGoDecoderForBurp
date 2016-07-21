package burp.decoder;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.List;

import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.Message;

import POGOProtos.Networking.Envelopes.ResponseEnvelopeOuterClass.ResponseEnvelope;
import POGOProtos.Networking.Requests.RequestTypeOuterClass.RequestType;
import burp.decoder.Decoder.ResponseDecoderHints.REQUEST_TYPES;

public class ResponseDecoder extends AbstractDecoder implements Decoder.IResponseDecoder {

	private final ResponseDecoderHints.REQUEST_TYPES hints;

	protected ResponseDecoder(byte[] message, MessageParsers parser, ResponseDecoderHints hints) {
		super(message, parser);
		if (!(hints instanceof ResponseDecoderHints.REQUEST_TYPES)) {
			throw new IllegalArgumentException("expected request types"); // TODO
																			// this
																			// sucsk
																			// hard
																			// -
																			// learn
																			// generics!
		}
		this.hints = (REQUEST_TYPES) hints;
	}

	@Override
	public Description decode() {

		ResponseEnvelope responseEnvelop;
		try {
			responseEnvelop = ResponseEnvelope.parseFrom(getMessage());

			List<ByteString> parsed = new ArrayList<>();

			for (int i = 0; i < responseEnvelop.getReturnsCount(); i++) {
				ByteString bytes = responseEnvelop.getReturns(i);
				bytes = decode(bytes);
				parsed.add(bytes);
			}

			injectPrivateObject(responseEnvelop, parsed, "returns_");
			return StringDescriptionFromMessage(responseEnvelop);
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	private ByteString decode(ByteString bytes) throws IOException {
		RequestType type = hints.getHints().removeFirst();
		Message foo = parseMesage(type, bytes);
		return toStringWithCheck(bytes, foo);
	}

}
