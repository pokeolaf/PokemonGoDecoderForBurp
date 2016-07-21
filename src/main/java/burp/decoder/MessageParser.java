package burp.decoder;

import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import com.google.common.base.CaseFormat;
import com.google.protobuf.ByteString;

import POGOProtos.Networking.Requests.RequestTypeOuterClass.RequestType;

public class MessageParser {

	private final Map<RequestType, Method> mapping;
	
	public MessageParser(String basePackage, String classNameSuffix) {
		Map<RequestType, Method> tmp = new HashMap<>();
		for (RequestType r : RequestType.values()) {
			Class<?> responseFoo = findClass(r, basePackage, classNameSuffix);
			if (responseFoo != null) {
				Method m = findParseFromMethod(responseFoo);
				if (m != null) {
					tmp.put(r, m);
				}
			} else {
			}
		}
		mapping = Collections.unmodifiableMap(tmp);
	}

	private Method findParseFromMethod(Class<?> responseFoo) {
		try {
			return responseFoo.getMethod("parseFrom", ByteString.class);
		} catch (NoSuchMethodException | SecurityException e) {
			throw new IllegalStateException("could not find parser method", e);
		}
	}

	private Class<?> findClass(RequestType r, String basePackage, String classNameSuffix) {
		String cc_name = CaseFormat.UPPER_UNDERSCORE.to(CaseFormat.UPPER_CAMEL, r.name()) + classNameSuffix;
		try {
			Class<?>[] a = Class.forName(basePackage + cc_name + "OuterClass")
					.getDeclaredClasses();
			return Arrays.stream(a).filter(c -> cc_name.equals(c.getSimpleName())).findAny().orElseGet(() -> {
				return null;
			});
		} catch (ClassNotFoundException e) {
			return null;
		}
	}

	public Method get(RequestType type) {
		return mapping.get(type);
	}

}
