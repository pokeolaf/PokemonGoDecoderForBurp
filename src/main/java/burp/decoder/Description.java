package burp.decoder;

public interface Description {
	public static Description EMPTY = new Description() {

		@Override
		public byte[] asBytes() {
			return new byte[0];
		}

		@Override
		public String asString() {
			return "";
		}
	};
	public static class BYTE implements Description{
		
		private final byte[] bytes;
		
		public BYTE(byte[] bytes) {
			super();
			this.bytes = bytes;
		}

		@Override
		public byte[] asBytes() {
			return bytes;
		}
		
		@Override
		public String asString() {
			return new String(bytes);
		}
	};
	public static class STRING implements Description{
		
		private final String s;
		
		public STRING(String s) {
			this.s = s;
		}
		
		@Override
		public byte[] asBytes() {
			return s.getBytes();
		}
		
		@Override
		public String asString() {
			return s;
		}
	};
	public byte[] asBytes();

	public String asString();
}
