package com.ljh.apiclient.configeditor;

import javax.swing.*;
import javax.swing.event.TreeModelEvent;
import javax.swing.event.TreeModelListener;
import java.awt.*;
import java.io.*;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Properties;

@SuppressWarnings("serial")
public class PropertiesEditorDemo extends JFrame implements TreeModelListener {

	private final PropertiesTreeTableModel treeTableModel;

	private  Object createSampleData() throws IOException, URISyntaxException {

		Map<String, Object> root = new LinkedHashMap<>();
		String props1=readPropStrs("requestEnc");
		String props2=readPropStrs("requestSign");
		String props3=readPropStrs("responseEnc");
		String props4=readPropStrs("responseSign");
		String props5=readPropStrs("keystoreType");
		String props6=readPropStrs("keystorePassword");
		String props7=readPropStrs("keystoreDest");
//		String[] str=s.split("\\s+ ");
		String[] strings4=props4.split("\\s+");
		String[] strings3=props3.split("\\s+");
		String[] strings2=props2.split("\\s+");
		String[] strings1=props1.split("\\s+");

		root.put("请求加密字段", Arrays.asList(strings1));
		root.put("请求签名字段", Arrays.asList(strings2));
		root.put("响应加密字段", Arrays.asList(strings3));
		root.put("响应签名字段", Arrays.asList(strings4));
		root.put("证书库类型", Arrays.asList(props5));
		root.put("证书库密码", Arrays.asList(props6));
		root.put("证书库路径", Arrays.asList(props7));

		return root;		

	}

	private PropertiesEditorDemo() throws IOException, URISyntaxException {
		setTitle("Properties Editor Demo");
		setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);
		setMinimumSize(new Dimension(700, 450));
		getRootPane().setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
		
		// the data types available in the editor can be configured as follows:
		
		 PropertiesEditorConfig.PropertiesEditorConfigBuilder configBuilder = PropertiesEditorConfig.builder();

		 configBuilder.addType(new PropertyTypes.MapType(""));

		 configBuilder.addType(new PropertyTypes.ListType(""));

//		 configBuilder.addDefaultType(new PropertyTypes.StringType("lll", ""));
		 configBuilder.addDefaultType(new PropertyTypes.StringType("test", ""));



		 PropertiesEditorConfig config = configBuilder.build();

		 treeTableModel = new PropertiesTreeTableModel(config, createSampleData());

//		treeTableModel = new PropertiesTreeTableModel(createSampleData());
		treeTableModel.addTreeModelListener(this);

		add(new PropertiesEditor(treeTableModel));


		setVisible(true);
	}

	public Properties getProperties() throws IOException, URISyntaxException {
		URL apiconfigurl = this.getClass().getClassLoader().getResource("ApiConfig.properties");
		File apiconfigfile = Paths.get(apiconfigurl.toURI()).toFile();
		Reader reader=new FileReader(apiconfigfile);
		Properties properties2=new Properties();
		properties2.load(reader);
		String path=properties2.getProperty("configFilePath");

		Properties properties=new Properties();
		BufferedReader bufferedReader=new BufferedReader(new FileReader(path+"\\CryptoConfig.properties"));
		properties.load(bufferedReader);
//        int mode= Integer.parseInt(properties.getProperty("workmode"));
		return properties;
	}

	public String readPropStrs(String propname) throws IOException, URISyntaxException {
		Properties properties=getProperties();
		String res=properties.getProperty(propname);
		return res;
	}

	@Override
	public void treeNodesChanged(TreeModelEvent e) {
		print();
	}

	@Override
	public void treeNodesInserted(TreeModelEvent e) {
		print();
	}

	@Override
	public void treeNodesRemoved(TreeModelEvent e) {
		print();
	}

	@Override
	public void treeStructureChanged(TreeModelEvent e) {
		print();
	}

	private void print() {
//		System.out.println(treeTableModel.getData());
	}

	public static void main(String[] args) throws IOException, URISyntaxException {
		new PropertiesEditorDemo();
	}

}
