package burp.decoder;
import java.io.IOException;

/**
 * An inner class for writing text to the output stream.
 */
public class TextGenerator {
	private final Appendable output;
	private final StringBuilder indent = new StringBuilder();
	private boolean atStartOfLine = true;

	public TextGenerator(final Appendable output) {
		this.output = output;
	}

	/**
	 * Indent text by two spaces. After calling Indent(), two spaces will be
	 * inserted at the beginning of each line of text. Indent() may be called
	 * multiple times to produce deeper indents.
	 */
	public void indent() {
		indent.append("  ");
	}

	/**
	 * Reduces the current indent level by two spaces, or crashes if the indent
	 * level is zero.
	 */
	public void outdent() {
		final int length = indent.length();
		if (length == 0) {
			throw new IllegalArgumentException(" Outdent() without matching Indent().");
		}
		indent.delete(length - 2, length);
	}

	/**
	 * Print text to the output stream.
	 */
	public void print(final CharSequence text) throws IOException {
		final int size = text.length();
		int pos = 0;

		for (int i = 0; i < size; i++) {
			if (text.charAt(i) == '\n') {
				write(text.subSequence(pos, i + 1));
				pos = i + 1;
				atStartOfLine = true;
			}
		}
		write(text.subSequence(pos, size));
	}

	private void write(final CharSequence data) throws IOException {
		if (data.length() == 0) {
			return;
		}
		if (atStartOfLine) {
			atStartOfLine = false;
			output.append(indent);
		}
		output.append(data);
	}
}