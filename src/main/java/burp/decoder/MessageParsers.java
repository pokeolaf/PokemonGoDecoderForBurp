package burp.decoder;

import java.lang.reflect.InvocationTargetException;

import com.google.protobuf.ByteString;
import com.google.protobuf.Message;

import POGOProtos.Networking.Requests.RequestTypeOuterClass.RequestType;

public enum MessageParsers {
	REQUEST("POGOProtos.Networking.Requests.Messages.", "Message"), RESPONSE("POGOProtos.Networking.Responses.",
			"Response");
	
	private final MessageParser parser;
	private final String basePackage;
	private final String classSuffix;

	private MessageParsers(String basePackage, String classSuffix) {
		this.basePackage = basePackage;
		this.classSuffix = classSuffix;
		this.parser = new MessageParser(basePackage, classSuffix);
	}

	public Message parse(RequestType type, ByteString bytes) {
		try {
			return (Message) parser.get(type).invoke(null, bytes);
		} catch (IllegalAccessException | IllegalArgumentException | InvocationTargetException e) {
			throw new RuntimeException(
					"parser not found, check compilation of " + basePackage + type.name() + classSuffix + ".proto", e);
		}
	}
}
