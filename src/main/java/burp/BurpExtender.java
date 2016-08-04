package burp;

import java.util.List;

import javax.swing.JMenuItem;

import burp.decoder.BurpBodyExtractor;
import burp.decoder.DecoderTab;

public class BurpExtender implements IBurpExtender, IMessageEditorTabFactory {
	IBurpExtenderCallbacks callbacks;

	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
		this.callbacks = callbacks;
		callbacks.setExtensionName("Pokemongo decoder");
		callbacks.registerMessageEditorTabFactory(this);
		callbacks.registerContextMenuFactory(new IContextMenuFactory() {
			
			@Override
			public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
				return null;
			}
		});
	}

	@Override
	public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
		IExtensionHelpers helpers = callbacks.getHelpers();
		DecoderTab tab = new DecoderTab(callbacks, controller, new BurpBodyExtractor(helpers));
		return tab;
	}
}
