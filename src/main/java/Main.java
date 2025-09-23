import com.alipay.api.AlipayClient;
import com.alipay.api.DefaultAlipayClient;
import com.alipay.api.request.AlipayDataBillBalanceQueryRequest;
import com.alipay.api.response.AlipayDataBillBalanceQueryResponse;
import com.alipay.api.request.AlipayDataBillAccountlogQueryRequest;
import com.alipay.api.response.AlipayDataBillAccountlogQueryResponse;
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpExchange;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

/**
 * 支付宝账单查询服务主类
 * 提供HTTP接口用于查询支付宝余额和账单明细
 */
public class Main {

    // 支付宝网关地址
    private static volatile String GATEWAY_URL;
    // 支付宝用户ID
    private static volatile String BILL_USER_ID;
    // 应用ID
    private static volatile String APP_ID;
    // 应用私钥
    private static volatile String APP_PRIVATE_KEY;
    // 支付宝公钥
    private static volatile String ALIPAY_PUBLIC_KEY;
    // 返回格式
    private static final String FORMAT = "json";
    // 字符编码
    private static final String CHARSET = "UTF-8";
    // 签名算法
    private static final String SIGN_TYPE = "RSA2";
    // 日期格式
    private static final String DATE_FORMAT = "yyyy-MM-dd HH:mm:ss";
    // 初始化支付宝配置
    private static volatile AlipayClient alipayClient;

    /**
     * 程序入口点，启动HTTP服务器并注册路由
     * 1. 加载支付宝配置参数
     * 2. 初始化支付宝客户端
     * 3. 创建HTTP服务器并注册请求处理器
     * 4. 启动服务器并监听8080端口
     *
     * @param args 命令行参数
     */
    public static void main(String[] args) {
        try {
            // 从配置文件加载参数
            loadConfig();

            // 初始化AlipayClient
            alipayClient = new DefaultAlipayClient(GATEWAY_URL, APP_ID, APP_PRIVATE_KEY, FORMAT, CHARSET, ALIPAY_PUBLIC_KEY, SIGN_TYPE);

            // 获取命令行参数中的端口号，默认为8080
            int port = 8080;
            if (args.length > 0) {
                try {
                    port = Integer.parseInt(args[0]);
                } catch (NumberFormatException e) {
                    System.err.println("无效的端口号参数: " + args[0] + "，将使用默认端口8080");
                }
            }

            // 创建HTTP服务器，监听指定端口
            HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);

            // 注册余额查询接口处理器
            server.createContext("/balance", new BalanceHandler());
            // 注册账单查询接口处理器
            server.createContext("/accountlog", new AccountLogHandler());
            // 注册签名生成接口处理器
            server.createContext("/sign", new SignHandler());

            server.setExecutor(null); // creates a default executor
            // 启动HTTP服务器
            server.start();

            System.out.println("服务器已启动，监听端口 " + port);
            System.out.println("访问 http://localhost:" + port + "/balance 查询支付宝余额");
            System.out.println("访问 http://localhost:" + port + "/accountlog 查询支付宝账单");
            System.out.println("访问 http://localhost:" + port + "/sign 生成签名");

        } catch (IOException e) {
            System.err.println("启动服务器失败: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * 解析表单数据
     * @param formData 表单数据字符串
     * @return 参数映射
     */
    private static Map<String, String> parseFormData(String formData) {
        Map<String, String> params = new HashMap<>();
        if (formData != null && !formData.isEmpty()) {
            String[] pairs = formData.split("&");
            for (String pair : pairs) {
                String[] keyValue = pair.split("=", 2);
                if (keyValue.length == 2) {
                    try {
                        String key = URLDecoder.decode(keyValue[0], "UTF-8");
                        String value = URLDecoder.decode(keyValue[1], "UTF-8");
                        params.put(key, value);
                    } catch (Exception e) {
                        // 解码失败则跳过该参数
                    }
                }
            }
        }
        return params;
    }

    /**
     * 签名生成处理器
     * 钉钉签名算法
     * 处理 /sign 路径的HTTP请求，根据动态提交的密钥生成签名
     */
    static class SignHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            try {
                if ("POST".equals(exchange.getRequestMethod())) {
                    // 获取请求体
                    String requestBody = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);

                    // 解析请求参数
                    Map<String, String> params = parseFormData(requestBody);
                    String secret = params.get("secret");

                    if (secret == null || secret.isEmpty()) {
                        sendResponse(exchange, "{\"error\":\"缺少secret参数\"}", 400);
                        return;
                    }

                    // 生成签名
                    Long timestamp = System.currentTimeMillis();
                    String stringToSign = timestamp + "\n" + secret;
                    Mac mac = Mac.getInstance("HmacSHA256");
                    mac.init(new SecretKeySpec(secret.getBytes("UTF-8"), "HmacSHA256"));
                    byte[] signData = mac.doFinal(stringToSign.getBytes("UTF-8"));
                    String sign = java.net.URLEncoder.encode(new String(org.apache.commons.codec.binary.Base64.encodeBase64(signData)), "UTF-8");

                    // 返回结果
                    String response = "{" +
                            "\"timestamp\":" + timestamp + "," +
                            "\"sign\":\"" + sign + "\"" +
                            "}";
                    sendResponse(exchange, response, 200);
                } else {
                    sendResponse(exchange, "{\"error\":\"只支持POST方法\"}", 405);
                }
            } catch (Exception e) {
                sendResponse(exchange, "{\"error\":\"生成签名失败: " + e.getMessage() + "\"}", 500);
            }
        }
    }

    /**
     * 从配置文件加载参数
     * 支持从多个位置加载配置文件，优先级为:
     * 1. 命令行参数指定的路径
     * 2. 当前目录下的alipay.properties文件
     * 3. classpath下的alipay.properties文件
     * 如果都找不到配置文件，则生成模板配置文件
     */
    private static void loadConfig() {
        try {
            Properties props = new Properties();

            // 首先尝试从命令行参数获取配置文件路径
            String configPath = System.getProperty("config.path");

            if (configPath != null && !configPath.isEmpty()) {
                // 如果指定了配置文件路径，则从指定路径加载
                System.out.println("从指定路径加载配置文件: " + configPath);
                try (FileReader reader = new FileReader(configPath)) {
                    props.load(reader);
                }
            } else {
                // 尝试从当前目录加载配置文件
                if (Files.exists(Paths.get("alipay.properties"))) {
                    System.out.println("从当前目录加载配置文件: alipay.properties");
                    try (FileReader reader = new FileReader("alipay.properties")) {
                        props.load(reader);
                    }
                } else {
                    // 尝试从classpath加载（适用于jar包内）
                    System.out.println("从classpath加载配置文件: alipay.properties");
                    try (InputStream input = Main.class.getClassLoader().getResourceAsStream("alipay.properties")) {
                        if (input != null) {
                            props.load(input);
                        } else {
                            // 如果所有位置都找不到配置文件，则生成一个新的模板配置文件
                            System.err.println("未找到配置文件 alipay.properties，正在生成模板配置文件...");
                            generateDefaultConfigFile();
                            System.err.println("已生成模板配置文件 alipay.properties，请修改配置后重新运行程序");
                            System.exit(1);
                        }
                    }
                }
            }

            // 读取配置项
            GATEWAY_URL = props.getProperty("gateway_url", "https://openapi.alipay.com/gateway.do");
            BILL_USER_ID = props.getProperty("bill_user_id", "").replace("\\n", "\n");
            APP_ID = props.getProperty("app_id", "");
            APP_PRIVATE_KEY = props.getProperty("app_private_key", "").replace("\\n", "\n");
            ALIPAY_PUBLIC_KEY = props.getProperty("alipay_public_key", "").replace("\\n", "\n");

            // 验证必需参数
            if (BILL_USER_ID.isEmpty() || APP_ID.isEmpty() || APP_PRIVATE_KEY.isEmpty() || ALIPAY_PUBLIC_KEY.isEmpty()) {
                System.err.println("配置文件中缺少必需参数");
                System.exit(1);
            }

            System.out.println("配置加载成功");
        } catch (Exception e) {
            System.err.println("加载配置文件时发生错误: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }

    /**
     * 生成默认的配置文件模板
     * 当找不到配置文件时，会自动生成一个包含示例配置的模板文件
     */
    private static void generateDefaultConfigFile() {
        try {
            String configContent = "# 支付宝配置文件\n" +
                    "# 请将下面的值替换为您自己的支付宝应用配置\n" +
                    "\n" +
                    "# 支付宝网关地址(无需更改)\n" +
                    "gateway_url=https://openapi.alipay.com/gateway.do\n" +
                    "\n" +
                    "# 支付宝用户ID（合作伙伴ID）\n" +
                    "bill_user_id=2088xxxxxxxxxxxx\n" +
                    "\n" +
                    "# 应用ID\n" +
                    "app_id=2021xxxxxxxxxxxx\n" +
                    "\n" +
                    "# 应用私钥（请使用您的私钥替换）\n" +
                    "app_private_key=-----BEGIN PRIVATE KEY-----\\n\\\n" +
                    "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7...\\n\\\n" +
                    "...\\n\\\n" +
                    "-----END PRIVATE KEY-----\n" +
                    "\n" +
                    "# 支付宝公钥（请使用支付宝提供的公钥替换）\n" +
                    "alipay_public_key=-----BEGIN PUBLIC KEY-----\\n\\\n" +
                    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...\\n\\\n" +
                    "...\\n\\\n" +
                    "-----END PUBLIC KEY-----\n";

            Files.write(Paths.get("alipay.properties"), configContent.getBytes(StandardCharsets.UTF_8));
            System.out.println("模板配置文件已生成: alipay.properties");
        } catch (IOException e) {
            System.err.println("生成模板配置文件失败: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * 余额查询处理器
     * 处理 /balance 路径的HTTP请求
     */
    static class BalanceHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            sendResponse(exchange, queryBalance(), 200);
        }
    }

    /**
     * 账单查询处理器
     * 处理 /accountlog 路径的HTTP请求
     */
    static class AccountLogHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            sendResponse(exchange, queryAccountLog(), 200);
        }
    }

    /**
     * 发送HTTP响应
     *
     * @param exchange   HTTP交换对象
     * @param response   响应内容
     * @param statusCode HTTP状态码
     * @throws IOException IO异常
     */
    private static void sendResponse(HttpExchange exchange, String response, int statusCode) throws IOException {
        OutputStream os = null;
        try {
            // 设置响应头
            exchange.getResponseHeaders().set("Content-Type", "application/json; charset=UTF-8");
            exchange.sendResponseHeaders(statusCode, response.getBytes(StandardCharsets.UTF_8).length);

            // 发送响应
            os = exchange.getResponseBody();
            os.write(response.getBytes(StandardCharsets.UTF_8));
        } finally {
            if (os != null) {
                try {
                    os.close();
                } catch (IOException e) {
                    // 忽略关闭流时的异常
                }
            }
        }
    }

    /**
     * 查询支付宝余额
     * 调用支付宝API查询账户余额信息
     *
     * @return 查询结果的JSON字符串
     */
    private static String queryBalance() {
        try {
            // 创建API请求对象
            AlipayDataBillBalanceQueryRequest request = new AlipayDataBillBalanceQueryRequest();

            // 设置请求参数
            String bizContent = "{" + "\"bill_user_id\":\"" + BILL_USER_ID + "\"," +  // 支付宝用户ID(2088开头)
                    "\"biz_type\":\"trade\"" +                  // 业务类型
                    "}";
            request.setBizContent(bizContent);

            // 执行API调用
            AlipayDataBillBalanceQueryResponse response = alipayClient.execute(request);

            // 处理响应结果
            if (response.isSuccess()) {
                return "{" + "\"success\":true," + "\"availableAmount\":\"" + response.getAvailableAmount() + "\"," + "\"freezeAmount\":\"" + response.getFreezeAmount() + "\"," + "\"totalAmount\":\"" + response.getTotalAmount() + "\"" + "}";
            } else {
                return "{" + "\"success\":false," + "\"errorCode\":\"" + response.getCode() + "\"," + "\"errorMsg\":\"" + response.getMsg() + "\"," + "\"subErrorCode\":\"" + response.getSubCode() + "\"," + "\"subErrorMsg\":\"" + response.getSubMsg() + "\"" + "}";
            }
        } catch (Exception e) {
            return "{" + "\"success\":false," + "\"errorCode\":\"EXCEPTION\"," + "\"errorMsg\":\"" + e.getMessage() + "\"" + "}";
        }
    }

    /**
     * 查询支付宝账单
     * 调用支付宝API查询账户账单明细，默认查询最近一周的数据
     *
     * @return 查询结果的JSON字符串
     */
    private static String queryAccountLog() {
        try {
            // 创建API请求对象
            AlipayDataBillAccountlogQueryRequest request = new AlipayDataBillAccountlogQueryRequest();

            // 设置请求参数（默认查询最近一周的数据）
            SimpleDateFormat sdf = new SimpleDateFormat(DATE_FORMAT);
            Date now = new Date();
            Date weekAgo = new Date(now.getTime() - 7L * 24 * 60 * 60 * 1000);//当前时间戳减7天

            String bizContent = "{" + "\"start_time\":\"" + sdf.format(weekAgo) + "\"," +//开始时间 7 天前
                    "\"end_time\":\"" + sdf.format(now) + "\"," +//结束时间 当前时间
                    "\"page_no\":\"1\"," +//分页号，从1开始（账单页）
                    "\"page_size\":\"20\"," +//分页大小（账单个数）
                    "}";
//                 "\"trans_code\":\"301101\"" + //业务类型101101,301101
            request.setBizContent(bizContent);

            // 执行API调用
            AlipayDataBillAccountlogQueryResponse response = alipayClient.execute(request);

            // 处理响应结果
            if (response.isSuccess()) {
                return (response.getDetailList() != null ? response.getBody() : "null");
            } else {
                return "{" + "\"success\":false," + "\"errorCode\":\"" + response.getCode() + "\"," + "\"errorMsg\":\"" + response.getMsg() + "\"," + "\"subErrorCode\":\"" + response.getSubCode() + "\"," + "\"subErrorMsg\":\"" + response.getSubMsg() + "\"" + "}";
            }
        } catch (Exception e) {
            return "{" + "\"success\":false," + "\"errorCode\":\"EXCEPTION\"," + "\"errorMsg\":\"" + e.getMessage() + "\"" + "}";
        }
    }
}
