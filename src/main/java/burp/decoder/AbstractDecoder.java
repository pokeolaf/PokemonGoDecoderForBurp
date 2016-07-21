package burp.decoder;

import java.lang.reflect.Field;
import java.util.Optional;

import com.google.protobuf.ByteString;
import com.google.protobuf.Message;

import POGOProtos.Networking.Requests.RequestTypeOuterClass.RequestType;

public abstract class AbstractDecoder implements Decoder {

	private final byte[] message;
	private final MessageParsers parser;

	protected AbstractDecoder(byte[] message, MessageParsers parser) {
		super();
		this.message = message;
		this.parser = parser;
	}

	protected byte[] getMessage() {
		return message;
	}

	protected Description StringDescriptionFromMessage(Message message) {
		return new Description.STRING(message.toString().replaceAll("\\\\n", "\n"));
	}

	protected Message parseMesage(RequestType type, ByteString bytes) {
		return parser.parse(type, bytes);
	}

	protected ByteString toStringWithCheck(ByteString bytes, Message foo) {
		String s = foo.toString();
		Optional<Integer> maxLength = getMaxLength();
		if (maxLength.isPresent()) {
			if (s.length() > maxLength.get()) {
				s = s.substring(0, maxLength.get()) + "...\n";
			}
		}
		if (foo.toByteString().size() != bytes.size()) {
			throw new RuntimeException("Proto definition fault for type: " + foo.getClass().getName());
		}
		return ByteString.copyFrom(s.getBytes());
	}

	private Optional<Integer> getMaxLength() {
		try {
			String prop = System.getProperty("message.maxLength");
			if (prop != null) {
				return (Optional.of(new Integer(prop)));
			} else {
				return Optional.empty();
			}
		} catch (NumberFormatException e) {
			return Optional.empty();
		}
	}

	protected void injectPrivateObject(Object object, Object injection, String fieldname) {
		try {
			Field field = object.getClass().getDeclaredField(fieldname);
			field.setAccessible(true);
			field.set(object, injection);
		} catch (NoSuchFieldException | SecurityException | IllegalArgumentException | IllegalAccessException e) {
			throw new RuntimeException(e);
		}

	};

}
