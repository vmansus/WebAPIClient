package com.ljh.apiclient.configeditor;

import javax.swing.*;
import java.io.*;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Paths;
import java.util.Properties;

public class CreateConfigFile {
    public static void main(String[] args) throws IOException, URISyntaxException {
        new CreateConfigFile().saveConfigFile();
    }
    public void saveConfigFile() throws IOException, URISyntaxException {
        JFileChooser chooser = new JFileChooser();

        chooser.setCurrentDirectory(new File("D:\\"));//设置默认目录 打开直接默认E盘

        chooser.setDialogTitle("保存文件位置");     //自定义选择框标题

        chooser.setDialogType(JFileChooser.SAVE_DIALOG);//设置为“保存”
        //chooser.setDialogType(JFileChooser.OPEN_DIALOG);//设置为“打开”

        //chooser.setApproveButtonText("保存");//设置按钮上的文字，默认是“保存”或者“打开”

        chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);//仅显示目录；有三种，仅文件，仅目录，两者都
        chooser.showSaveDialog(null);//show”保存“
        //chooser.showOpenDialog(null);//show“打开”

        //chooser.setSelectedFile(new File("defaultFileName")); //设置默认文件名

        String path = chooser.getSelectedFile().getPath();//获取路径

        System.out.println(path);

        URL res = getClass().getClassLoader().getResource("demo.properties");
        System.out.println(res);
        File source = Paths.get(res.toURI()).toFile();
        File dest=new File(path,"CryptoConfig.properties");
        copyFileUsingFileStreams(source,dest);

        URL rs = getClass().getClassLoader().getResource("ApiConfig.properties");
        File rss = Paths.get(rs.toURI()).toFile();

        Reader reader=new FileReader(rss);
        Properties properties=new Properties();
        properties.load(reader);
        properties.setProperty("configFilePath",path);

        FileWriter fileWriter=new FileWriter(rss);
        properties.store(fileWriter,"Change configFilePath to "+path);

        Reader reader2=new FileReader(rss);
        Properties properties2=new Properties();
        properties2.load(reader2);
        System.out.println(properties2.getProperty("configFilePath"));



    }

    private static void copyFileUsingFileStreams(File source, File dest)
            throws IOException {
        InputStream input = null;
        OutputStream output = null;
        try {
            input = new FileInputStream(source);
            output = new FileOutputStream(dest);
            byte[] buf = new byte[1024];
            int bytesRead;
            while ((bytesRead = input.read(buf)) > 0) {
                output.write(buf, 0, bytesRead);
            }
        } finally {
            input.close();
            output.close();
        }
    }
}
