package burp.decoder;

import java.util.Deque;

import POGOProtos.Networking.Requests.RequestTypeOuterClass.RequestType;

public interface Decoder {

	static interface ResponseDecoderHints {

		static class REQUEST_TYPES implements ResponseDecoderHints {
			private final Deque<RequestType> requestTypeStack;

			public REQUEST_TYPES(Deque<RequestType> requestStack) {
				super();
				this.requestTypeStack = requestStack;
			}

			public Deque<RequestType> getHints() {
				return requestTypeStack;
			}

		}
	}

	static interface IResponseDecoder extends Decoder {
	}

	static interface IRequestDecoder extends Decoder {
		ResponseDecoderHints getResponseDecoderHints();
	}

	static interface FinalDecoderBuilder<T extends Decoder> {
		T build();
	}

	static interface ResponseDecoderBuilder {
		FinalDecoderBuilder<IResponseDecoder> putResponseDecoderHints(ResponseDecoderHints hints);
	}

	static interface DecoderBuilder {
		FinalDecoderBuilder<IRequestDecoder> putRequest(byte[] request);

		ResponseDecoderBuilder putResponse(byte[] response);
	}

	public static class DecoderFactory implements DecoderBuilder, ResponseDecoderBuilder {

		private byte[] message;
		private ResponseDecoderHints hints;

		private FinalDecoderBuilder<IRequestDecoder> requstDecoderFactory = new FinalDecoderBuilder<IRequestDecoder>() {

			@Override
			public IRequestDecoder build() {
				return new RequestDecoder(message, MessageParsers.REQUEST);
			}

		};
		private FinalDecoderBuilder<IResponseDecoder> responseDecoderFactory = new FinalDecoderBuilder<IResponseDecoder>() {

			@Override
			public IResponseDecoder build() {
				return (IResponseDecoder) new ResponseDecoder(message, MessageParsers.RESPONSE, hints);
			}

		};

		private DecoderFactory() {
			super();
		}

		public static DecoderFactory newBuilder() {
			return new DecoderFactory();
		}

		@Override
		public FinalDecoderBuilder<IRequestDecoder> putRequest(byte[] request) {
			this.message = request;
			return requstDecoderFactory;
		}

		@Override
		public ResponseDecoderBuilder putResponse(byte[] response) {
			this.message = response;
			return this;
		}

		@Override
		public FinalDecoderBuilder<IResponseDecoder> putResponseDecoderHints(ResponseDecoderHints hints) {
			this.hints = hints;
			return responseDecoderFactory;
		}

	}

	Description decode();

}
