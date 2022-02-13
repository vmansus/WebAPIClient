package com.ljh.apiclient.configeditor;

import com.alibaba.fastjson.JSONObject;

import javax.swing.*;
import javax.swing.table.TableColumnModel;
import javax.swing.tree.TreePath;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.*;
import java.util.Properties;
@SuppressWarnings("serial")
public class PropertiesEditor extends JPanel {

	private final PropertiesTreeTable treeTable;

	private final PropertiesTreeTableModel treeTableModel;

	private JButton addButton;

	private JButton removeButton;
	private JButton saveButton;
	private JButton exitButton;
	String workmode;
	String iswholemode;
	String algmode;

	public PropertiesEditor(PropertiesTreeTableModel treeTableModel) throws IOException {

		setLayout(new GridBagLayout());

		this.treeTableModel = treeTableModel;
		treeTable = new PropertiesTreeTable(treeTableModel.getConfig(), treeTableModel);

		treeTable.addTreeSelectionListener(e -> updateButtons());

		// clear the selection, when clicking on an empty area of the table;
		// see here: http://stackoverflow.com/a/43443397
		treeTable.addMouseListener(new MouseAdapter() {
			@Override
			public void mousePressed(MouseEvent e) {
//				System.out.println(111);
				TreePath path = treeTable.getPathForLocation(e.getX(), e.getY());
				if (path == null) {

					treeTable.clearSelection();

					ListSelectionModel selectionModel = treeTable.getSelectionModel();
					selectionModel.setAnchorSelectionIndex(-1);
					selectionModel.setLeadSelectionIndex(-1);

					TableColumnModel columnModel = treeTable.getColumnModel();
					columnModel.getSelectionModel().setAnchorSelectionIndex(-1);
					columnModel.getSelectionModel().setLeadSelectionIndex(-1);

				}
			}
		});

		treeTable.expandAll();

		GridBagConstraints c = new GridBagConstraints();
		c.fill = GridBagConstraints.BOTH;
		c.gridx = 0;
		c.gridy = 0;
		c.weightx = 1;
		c.weighty = 1;
		add(new JScrollPane(treeTable), c);

		c.fill = GridBagConstraints.NONE;
		c.anchor = GridBagConstraints.NORTHWEST;
		c.gridx++;
		c.weightx = 0;
		add(createButtons(), c);


		c.fill = GridBagConstraints.NONE;
		c.anchor = GridBagConstraints.WEST;
		c.weightx = 0;
		add(creatMultiButtonGroups(), c);


		c.fill = GridBagConstraints.NONE;
		c.anchor = GridBagConstraints.SOUTHWEST;
		c.weightx = 0;
		add(createsaveexitttons(), c);

		updateButtons();
	}

	private void updateButtons() {
		int[] selectedRows = treeTable.getSelectedRows();
		removeButton.setEnabled(selectedRows.length > 0);
//		System.out.println("1111");
	}

	private Component creatMultiButtonGroups() throws IOException{
		JPanel buttonPanel = new JPanel();
		buttonPanel.setLayout(new GridLayout(3,1));
		String wmode=readPropStrs("workmode");
		String imode=readPropStrs("isWhole");
		String emode=readPropStrs("encAlg");
		ButtonGroup bg1=new ButtonGroup();
		ButtonGroup bg2=new ButtonGroup();
		ButtonGroup bg3=new ButtonGroup();
		JRadioButton jrb1=new JRadioButton("签名加密");			//创建单选框
		JRadioButton jrb2=new JRadioButton("仅加密");
		JRadioButton jrb3=new JRadioButton("仅签名");
		JRadioButton jrb4=new JRadioButton("分段");			//创建单选框
		JRadioButton jrb5=new JRadioButton("整体");
		JRadioButton jrb6=new JRadioButton("块加密");			//创建单选框
		JRadioButton jrb7=new JRadioButton("流加密");


		bg1.add(jrb1);
		bg1.add(jrb2);
		bg1.add(jrb3);

		bg2.add(jrb4);
		bg2.add(jrb5);

		bg3.add(jrb6);
		bg3.add(jrb7);

		if(wmode.equals("0")){
			jrb1.doClick();
		}else if(wmode.equals("1")){
			jrb2.doClick();
		}else if (wmode.equals("2")){
			jrb3.doClick();
		}else{
			System.out.println("workmode设置错误！！！");

		}

		jrb1.addActionListener((actionEvent -> {
			workmode="0";
		}));
		jrb2.addActionListener((actionEvent -> {
			workmode="1";
		}));
		jrb3.addActionListener((actionEvent -> {
			workmode="2";
		}));

		if(imode.equals("0")){
			jrb4.doClick();
		}else if(imode.equals("1")){
			jrb5.doClick();
		}else{
			System.out.println("isWholemode设置错误！！！");

		}

		jrb4.addActionListener((actionEvent -> {
			iswholemode="0";
		}));
		jrb5.addActionListener((actionEvent -> {
			iswholemode="1";
		}));

		if(emode.equals("0")){
			jrb6.doClick();
		}else if(emode.equals("1")){
			jrb7.doClick();
		}else{
			System.out.println("algmode设置错误！！！");

		}

		jrb6.addActionListener((actionEvent -> {
			algmode="0";
		}));
		jrb7.addActionListener((actionEvent -> {
			algmode="1";
		}));


		Box verticalBox1 = Box.createVerticalBox();
		verticalBox1.add(jrb1);
		verticalBox1.add(jrb2);
		verticalBox1.add(jrb3);
		Box verticalBox2 = Box.createVerticalBox();
		verticalBox2.add(jrb4);
		verticalBox2.add(jrb5);
		Box verticalBox3 = Box.createVerticalBox();
		verticalBox3.add(jrb6);
		verticalBox3.add(jrb7);

		buttonPanel.add(verticalBox1);
		buttonPanel.add(verticalBox2);
		buttonPanel.add(verticalBox3);



		return buttonPanel;


	}


	private Component createButtons() {
		JPanel buttonPanel = new JPanel(new GridBagLayout());

		GridBagConstraints c = new GridBagConstraints();
		c.fill = GridBagConstraints.HORIZONTAL;
		c.gridy = 0;

		addButton = new JButton("增加");
		addButton.addActionListener(e -> {

			PropertyNode newProperty = new PropertyNode(null, treeTableModel.getConfig().getDefaultType());

			if (treeTable.getSelectedRow() == -1) {


				//注释掉这里Add就无法选中空白区域

				// at the bottom of the root element
//				treeTableModel.insertNodeInto(newProperty, (PropertyNode) treeTableModel.getRoot(),
//						treeTableModel.getRoot().getChildCount());

			} else {

				TreePath path = treeTable.getPathForRow(treeTable.getSelectedRow());
				PropertyNode item = (PropertyNode) path.getPathComponent(path.getPathCount() - 1);

				if (item.getAllowsChildren()) {
					// if the selected item allows children, add child
					treeTableModel.insertNodeInto(newProperty, item, 0);

				} else {
					// else, add it as ancestor below the current selection
					treeTableModel.insertNodeInto(newProperty, (PropertyNode) item.getParent(),
							item.getParent().getIndex(item) + 1);
				}

			}

		});
		buttonPanel.add(addButton, c);
		c.gridy++;
		removeButton = new JButton("删除");
		buttonPanel.add(removeButton, c);

		removeButton.addActionListener(e -> {
			int[] selectedRows = treeTable.getSelectedRows();
			for (int i = selectedRows.length - 1; i >= 0; i--) {
				TreePath path = treeTable.getPathForRow(selectedRows[i]);
				PropertyNode propertyToRemove = (PropertyNode) path.getPathComponent(path.getPathCount() - 1);
				treeTableModel.removeNodeFromParent(propertyToRemove);
			}
		});
		return buttonPanel;
	}
	private Component createsaveexitttons() {
		JPanel buttonPanel = new JPanel(new GridBagLayout());

		GridBagConstraints c = new GridBagConstraints();
		c.fill = GridBagConstraints.HORIZONTAL;
		c.gridy = 0;



		c.gridy++;
		saveButton = new JButton("保存");
		exitButton = new JButton("退出");


		buttonPanel.add(saveButton, c);
		c.gridy++;
		buttonPanel.add(exitButton, c);
		saveButton.addActionListener((actionEvent -> {
//			JSONObject jsonObject=JSONObject.parseObject(treeTableModel.getData().toString());
			String a=treeTableModel.getData().toString();
			String ss=a.replace('=',':')
					.replace("请求加密字段","\"请求加密字段\"")
					.replace("响应加密字段","\"响应加密字段\"")
					.replace("响应签名字段","\"响应签名字段\"")
					.replace("请求签名字段","\"请求签名字段\"")
					.replace("[","\"")
					.replace("]","\"");
//			System.out.println(ss);

			JSONObject jsonObject=JSONObject.parseObject(ss);
			String str1= (String) jsonObject.get("请求加密字段");
			String str2= (String) jsonObject.get("请求签名字段");
			String str3= (String) jsonObject.get("响应加密字段");
			String str4= (String) jsonObject.get("响应签名字段");
			String[] strings1=str1.split(",");
			String[] strings2=str2.split(",");
			String[] strings3=str3.split(",");
			String[] strings4=str4.split(",");
			StringBuilder sb1=new StringBuilder();
			StringBuilder sb2=new StringBuilder();
			StringBuilder sb3=new StringBuilder();
			StringBuilder sb4=new StringBuilder();
			for (int i=0;i<strings1.length;i++){
				sb1.append(strings1[i]);
				sb1.append(" ");
			}
			for (int i=0;i<strings2.length;i++){
				sb2.append(strings2[i]);
				sb2.append(" ");
			}
			for (int i=0;i<strings3.length;i++){
				sb3.append(strings3[i]);
				sb3.append(" ");
			}
			for (int i=0;i<strings4.length;i++){
				sb4.append(strings4[i]);
				sb4.append(" ");
			}




			try {
				writePropstrs("requestEnc",sb1.toString());
				writePropstrs("requestSign",sb2.toString());
				writePropstrs("responseEnc",sb3.toString());
				writePropstrs("responseSign",sb4.toString());
			} catch (IOException e) {
				e.printStackTrace();
			}
			if(workmode!=null&&workmode.length()>0){
				try {
					writePropstrs("workmode",workmode);
				} catch (IOException e) {
					e.printStackTrace();
				}
			}

			if(iswholemode!=null&&iswholemode.length()>0){
				try {
					writePropstrs("isWhole",iswholemode);
				} catch (IOException e) {
					e.printStackTrace();
				}
			}

			if(algmode!=null&&algmode.length()>0){
				try {
					writePropstrs("encAlg",algmode);
				} catch (IOException e) {
					e.printStackTrace();
				}
			}

		}));
		exitButton.addActionListener((actionEvent -> {
			Window.getOwnerlessWindows()[0].dispose();
		}));
		return buttonPanel;
	}
	/**
	 * @return The model.
	 */
	public PropertiesTreeTableModel getTreeTableModel() {
		return treeTableModel;
	}
	
	/**
	 * @return The tree table.
	 */
	public PropertiesTreeTable getTreeTable() {
		return treeTable;
	}

	public static Properties getProperties() throws IOException {
		Properties properties=new Properties();
		BufferedReader bufferedReader=new BufferedReader(new FileReader("D:\\githuba\\apiclient\\src\\main\\resources\\CryptoConfig.properties"));
		properties.load(bufferedReader);
//        int mode= Integer.parseInt(properties.getProperty("workmode"));
		return properties;
	}

	public String readPropStrs(String propname) throws IOException {
		Properties properties=getProperties();
		String res=properties.getProperty(propname);
		return res;
	}

	public void writePropstrs(String propname ,String value) throws IOException{
		Properties properties=getProperties();
		properties.setProperty(propname,value);
		File file=new File("D:\\githuba\\apiclient\\src\\main\\resources\\CryptoConfig.properties");
		FileWriter fileWriter=new FileWriter(file);
		properties.store(fileWriter,"Change "+propname+" to "+value);
	}

}
