package burp.decoder;

import java.lang.reflect.InvocationTargetException;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;

import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.Message;

import POGOProtos.Networking.Envelopes.RequestEnvelopeOuterClass.RequestEnvelope;
import POGOProtos.Networking.Requests.RequestOuterClass.Request;
import POGOProtos.Networking.Requests.RequestTypeOuterClass.RequestType;

public class RequestDecoder extends AbstractDecoder implements burp.decoder.Decoder.IRequestDecoder {

	protected RequestDecoder(byte[] message, MessageParsers parser) {
		super(message, parser);
	}

	private final Deque<RequestType> requestStack = new ArrayDeque<>();

	@Override
	public Description decode() {
		try {
			RequestEnvelope requestEnvelop = parseFrom(getMessage());
			List<Request> parsedRequests = new ArrayList<>();
			for (Request request : requestEnvelop.getRequestsList()) {
				requestStack.addLast(request.getRequestType());
				parsedRequests.add(parseFrom(request));
			}
			injectPrivateObject(requestEnvelop, parsedRequests, "requests_");
			return new Description.STRING(requestEnvelop.toString());
		} catch (InvalidProtocolBufferException e) {
			throw new RuntimeException(e);
		}
	}

	protected RequestEnvelope parseFrom(byte[] message) throws InvalidProtocolBufferException {
		return RequestEnvelope.parseFrom(message);
	}

	private Request parseFrom(Request request) {
		Message foo = parseMesage(request.getRequestType(), request.getRequestMessage());
		ByteString bytes = toStringWithCheck(request.getRequestMessage(), foo);
		injectPrivateObject(request, bytes, "requestMessage_");
		return request;
	}

	public Deque<RequestType> getRequestStack() {
		return requestStack;
	}

	@Override
	public ResponseDecoderHints getResponseDecoderHints() {
		return new ResponseDecoderHints.REQUEST_TYPES(requestStack);
	}

}
