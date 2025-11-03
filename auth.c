#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <time.h>
#include <sys/types.h>
#include <sys/wait.h> // For waitpid()

// --- 配置常量 ---
// 认证服务器信息
#define AUTH_HOSTNAME "10.1.1.1"
#define AUTH_PORT "801"
char AUTH_PATH[256] = {0};

// --- 行为常量 ---
#define BUFFER_SIZE 4096
#define PING_TARGET "1.1.1.1"               // 网络检查的目标主机
#define PING_TIMEOUT_SECONDS 2              // ping命令超时时间
#define NETWORK_CHECK_INTERVAL_SECONDS 10   // 网络正常时的检查间隔
#define AUTH_RETRY_INTERVAL_SECONDS 10      // 认证失败后的重试等待时间
#define AUTH_COOLDOWN_SECONDS 60            // 两次认证之间的最短时间间隔
#define LOG_INTERVAL_SECONDS (5 * 60)       // 网络正常时，打印日志的间隔

// 认证结果枚举
typedef enum {
    AUTH_SUCCESS = 0,               // 认证成功
    AUTH_STATE_KEPT = 1,            // 状态保持 (已在线)
    AUTH_FAIL_GETADDRINFO = -1,     // DNS解析失败
    AUTH_FAIL_SOCKET_CREATE = -2,   // 创建socket失败
    AUTH_FAIL_CONNECT = -3,         // 连接服务器失败
    AUTH_FAIL_SEND = -4,            // 发送请求失败
    AUTH_FAIL_RECV = -5,            // 接收响应失败
    AUTH_FAIL_INVALID_RESPONSE = -6,// 无效的HTTP响应 (非200 OK)
    AUTH_FAIL_API_ERROR = -7,       // 认证接口返回失败 (ret_code: 1)
    AUTH_FAIL_UNKNOWN_RESPONSE = -8,// 未知的响应内容
    AUTH_FAIL_PARSE_ERROR = -9      // 响应解析失败
} AuthResult;

// 函数声明
char* url_encode(unsigned char *s, char *enc);
int writeLog(const char* tag, const char* msg);
AuthResult authenticate();
int is_network_available();
AuthResult parse_auth_response(char* buffer);
void log_response_body(char* buffer, const char* reason);

#ifdef _CR660X
void reset_leds(void){
    system("echo -n '' > /sys/class/leds/yellow:net/trigger");
    system("echo 0 > /sys/class/leds/yellow:net/brightness");
    system("echo -n '' > /sys/class/leds/blue:net/trigger");
    system("echo 0 > /sys/class/leds/blue:net/brightness");
    writeLog("认证程序", "认证程序已重置LED并退出");
}
#endif

void sigterm_handler(int sig){
    writeLog("认证程序", "接收到SIGTERM，即将退出");
    exit(0);
}

void sigint_handler(int sig){
    writeLog("认证程序", "接收到SIGINT，即将退出");
    exit(0);
}


int main(int argc, char *argv[]) {
    if(argc < 5){
        printf("usage: %s <account:string> <password:string> <isp:[0:telecomn|1:unicomn|2:cmccn] <mauthid:int>", argv[0]);
        exit(0);
    }
    char account[64];
    char password[128];
    url_encode((unsigned char *)argv[1], account);
    url_encode((unsigned char *)argv[2], password);
    char *isp;
    switch(atoi(argv[3])){
        case 0:
            isp = "telecomn";
            break;
        case 1:
            isp = "unicomn";
            break;
        case 2:
            isp = "cmccn";
            break;
        default:
            printf("isp must be 0, 1 or 2\n");
            exit(0);
    }
    sprintf(AUTH_PATH, "/eportal/portal/login?user_account=%2C0%2C%s%40%s&user_password=%s", account, isp, password);
    time_t last_auth_time = 0;      // 上次认证时间戳
    time_t last_log_time = 0;       // 上次打印"网络可用"日志的时间戳
#ifdef _CR660X
    atexit(reset_leds);
#endif
    signal(SIGTERM, sigterm_handler);
    signal(SIGINT, sigint_handler);
    while (1) {
        if (is_network_available()) {
            time_t current_time = time(NULL);
            sleep(NETWORK_CHECK_INTERVAL_SECONDS);
            continue;
        }

#ifdef _CR660X
        // 设置橙色led常亮，关闭蓝色led
        system("echo -n '' > /sys/class/leds/blue:net/trigger");
        system("echo 0 > /sys/class/leds/blue:net/brightness");
        system("echo -n '' > /sys/class/leds/yellow:net/trigger");
        system("echo 1 > /sys/class/leds/yellow:net/brightness");
#endif
        
        if (is_network_available()) continue;

        if (is_network_available()) continue;

        if (is_network_available()) continue;

        if (is_network_available()) continue;

           writeLog("网络状态检查", "网络不可用，尝试重新认证");
        time_t current_time = time(NULL);

        // 检查认证冷却时间，避免过于频繁地认证
        if (current_time - last_auth_time < AUTH_COOLDOWN_SECONDS) {
            writeLog("校园网认证", "认证操作过于频繁，等待中...");
            sleep(AUTH_RETRY_INTERVAL_SECONDS);
            continue;
        }
#ifdef _CR660X
        // led全亮
        system("echo 1 > /sys/class/leds/yellow:net/brightness");
        system("echo 1 > /sys/class/leds/blue:net/brightness");
#endif
        writeLog("校园网认证", "======== 开始认证过程 ========");
        AuthResult result = authenticate();
        last_auth_time = time(NULL); // 更新认证时间戳

        switch (result) {
            case AUTH_SUCCESS:
#ifdef _CR660X
                // 关闭橙色led,蓝色led亮
                system("echo -n '' > /sys/class/leds/yellow:net/trigger");
                system("echo 0 > /sys/class/leds/yellow:net/brightness");
                system("echo 1 > /sys/class/leds/blue:net/brightness");
                system("echo -n '' > /sys/class/leds/blue:net/trigger");
#endif
                writeLog("校园网认证", "认证成功");
                break;
            case AUTH_STATE_KEPT:
#ifdef _CR660X
                // 关闭橙色led,蓝色led亮
                system("echo -n '' > /sys/class/leds/yellow:net/trigger");
                system("echo 0 > /sys/class/leds/yellow:net/brightness");
                system("echo -n '' > /sys/class/leds/blue:net/trigger");
                system("echo 1 > /sys/class/leds/blue:net/brightness");
#endif
                writeLog("校园网认证", "状态保持 (已在线)");
                break;
            default:
#ifdef _CR660X
                // 其他情况均为失败，橙色led心跳，关闭蓝色led
                system("echo 1 > /sys/class/leds/yellow:net/brightness");
                system("echo -n 'heartbeat' > /sys/class/leds/yellow:net/trigger");
                system("echo 0 > /sys/class/leds/blue:net/brightness");
                system("echo -n '' > /sys/class/leds/blue:net/trigger");
#endif
                writeLog("校园网认证", "认证失败");
                break;
        }
        writeLog("校园网认证", "======== 结束认证过程 ========");
        last_log_time = 0; // 重置日志时间戳，确保下次网络可用时能立即打印日志
        sleep(AUTH_RETRY_INTERVAL_SECONDS);
    }

    return 0; // 永不执行
}

/**
 * @brief 使用 ping 命令检查网络连通性
 * @return 如果网络可用返回 1，否则返回 0
 */
int is_network_available() {
    char command[256];
    snprintf(command, sizeof(command), "ping -w %d -c 1 %s > /dev/null 2>&1",
             PING_TIMEOUT_SECONDS, PING_TARGET);
    int ret = system(command);
    return (ret == 0);
}

/**
 * @brief 执行校园网认证
 * @return AuthResult 枚举，表示认证结果
 */
AuthResult authenticate() {
    struct addrinfo hints, *res = NULL;
    int sockfd = -1;
    AuthResult status = AUTH_FAIL_UNKNOWN_RESPONSE; // 默认失败状态

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(AUTH_HOSTNAME, AUTH_PORT, &hints, &res) != 0) {
        perror("getaddrinfo");
        writeLog("认证错误", "获取地址信息失败 (DNS)");
        return AUTH_FAIL_GETADDRINFO;
    }

    sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sockfd < 0) {
        perror("socket");
        writeLog("认证错误", "创建socket失败");
        status = AUTH_FAIL_SOCKET_CREATE;
        goto cleanup;
    }

    if (connect(sockfd, res->ai_addr, res->ai_addrlen) < 0) {
        perror("connect");
        writeLog("认证错误", "连接认证服务器失败");
        status = AUTH_FAIL_CONNECT;
        goto cleanup;
    }

    char request[512];
    snprintf(request, sizeof(request),
             "GET %s HTTP/1.1\r\n"
             "Host: %s\r\n"
             "Connection: close\r\n\r\n",
             AUTH_PATH, AUTH_HOSTNAME);

    if (send(sockfd, request, strlen(request), 0) < 0) {
        perror("send");
        writeLog("认证错误", "发送认证请求失败");
        status = AUTH_FAIL_SEND;
        goto cleanup;
    }

    char buffer[BUFFER_SIZE];
    int bytes = recv(sockfd, buffer, sizeof(buffer) - 1, 0);
    if (bytes < 0) {
        perror("recv");
        writeLog("认证错误", "接收服务器响应失败");
        status = AUTH_FAIL_RECV;
        goto cleanup;
    }
    buffer[bytes] = '\0'; // 保证字符串结束

    status = parse_auth_response(buffer);

cleanup:
    if (sockfd >= 0) {
        close(sockfd);
    }
    if (res != NULL) {
        freeaddrinfo(res);
    }
    return status;
}

/**
 * @brief 解析认证服务器的响应
 * @param buffer 包含HTTP响应的字符串
 * @return AuthResult 枚举，表示解析结果
 */
AuthResult parse_auth_response(char* buffer) {

    if (strstr(buffer, "200 OK") == NULL) {
        writeLog("认证错误", "HTTP响应状态非200");
        writeLog("认证响应", buffer);
        return AUTH_FAIL_INVALID_RESPONSE;
    }

    if (strstr(buffer, "\"ret_code\":0") != NULL || strstr(buffer, "Portal协议认证成功！") != NULL) {
        log_response_body(buffer, "认证成功响应");
        return AUTH_SUCCESS;
    }
    
    if (strstr(buffer, "\"ret_code\":1") != NULL) {
        log_response_body(buffer, "认证失败响应 (ret_code 1)");
        return AUTH_FAIL_API_ERROR;
    }

    if (strstr(buffer, "\"ret_code\":2") != NULL) {
        log_response_body(buffer, "状态保持响应 (ret_code 2)");
        return AUTH_STATE_KEPT;
    }
    
    log_response_body(buffer, "未知响应");
    return AUTH_FAIL_UNKNOWN_RESPONSE;
}

/**
 * @brief 从形如 "callback({...})" 的响应中提取并记录JSON部分
 * @param buffer 完整的响应字符串 (会被strtok修改)
 * @param reason 日志标签
 */
void log_response_body(char* buffer, const char* reason) {
    char* header = strtok(buffer, "(");
    if (header == NULL) {
        writeLog("响应解析错误", "未找到左括号");
        writeLog(reason, buffer);
        return;
    }

    char* body = strtok(NULL, ")");
    if (body != NULL) {
        writeLog(reason, body);
    } else {
        writeLog("响应解析错误", "未找到右括号");
        writeLog(reason, buffer); // 记录原始buffer以便调试
    }
}


/**
 * @brief 安全地将日志写入系统日志 (syslog)
 * 使用 fork 和 execlp 替代 system，以防止命令注入
 * @param tag 日志标签
 * @param msg 日志消息
 * @return 成功返回 0，失败返回 -1
 */
int writeLog(const char* tag, const char* msg) {
    // 原始代码同时输出到 stderr 和 syslog
    // logger 的 -s 选项可以将消息同时输出到 stderr，-t 设置标签
    // 因此命令是 logger -s -t <tag> <msg>

    char timeStr[64];
    time_t now = time(NULL);
    strftime(timeStr, sizeof(timeStr), "%Y-%m-%d %H:%M:%S", localtime(&now));
    fprintf(stderr, "[%s] ", timeStr);

    pid_t pid = fork();
    if (pid == -1) {
        // Fork失败，这是一个严重的系统问题
        perror("fork");
        return -1;
    } else if (pid == 0) {
        // --- 子进程 ---
        // 使用 execlp 执行 logger 命令
        // 参数列表：程序名, argv[0], argv[1], argv[2], ..., NULL
        // shell 不会解释这些参数，因此是安全的
        execlp("logger", "logger", "-s", "-t", tag, msg, (char *)NULL);

        // 如果 execlp 返回，说明它执行失败了
        perror("execlp logger");
        exit(EXIT_FAILURE); // 子进程必须退出
    } else {
        // --- 父进程 ---
        int status;
        // 等待子进程结束，避免产生僵尸进程
        if (waitpid(pid, &status, 0) == -1) {
            perror("waitpid");
            return -1;
        }

        if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
            return 0; // 子进程正常退出且返回值为0
        }
        return -1; // 子进程异常退出
    }
}

/**
 * @brief 对字符串进行URL编码
 * @param s 待编码的字符串
 * @param enc 编码后的字符串
 * @return 编码后的字符串末尾指针
 */
char *url_encode(unsigned char *s, char *enc){

    for (; *s; s++){
        sprintf( enc, "%%%02X", *s);
        while (*++enc);
    }
    return( enc);
}