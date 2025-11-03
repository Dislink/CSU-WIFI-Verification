#!/bin/ash

# ==============================================================================
# Configuration
# ==============================================================================

# 时间间隔配置 (秒)
ONLINE_CHECK_INTERVAL=10   # 网络正常时的检查间隔
AUTH_RETRY_INTERVAL=10      # 认证失败后的重试等待时间
AUTH_COOLDOWN=60            # 两次认证之间的最短间隔
LOG_INTERVAL=$((5 * 60))    # 网络正常时，打印日志的间隔


# ==============================================================================
# Functions
# ==============================================================================

# 统一的日志函数，同时输出到控制台和系统日志(syslog)
write_log() {
    local tag="$1"
    local msg="$2"
    # 输出到标准错误，方便在控制台直接查看
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$tag] $msg" >&2
    # 使用 logger 命令写入系统日志
    logger -t "$tag" "$msg" 2>/dev/null
}

# 检查是否在线
check_online() {
    local response
    response=$(curl -s --interface "$interface" --connect-timeout 5 'http://10.1.1.1/drcom/chkstatus?callback=')
    if echo "$response" | grep -q '"result":0'; then
	rm -f "/tmp/auth/${interface}_${account}_${isp}"
        return 1  # 在线
    else
	touch "/tmp/auth/${interface}_${account}_${isp}"
        return 0  # 离线
    fi
}

# 执行认证
# 返回值约定:
# 0: 认证成功
# 1: 状态保持 (已在线)
# 2: 认证失败 (API返回错误)
# 3: HTTP请求失败或响应码非200
# 4: 未知响应
authenticate() {
    
    # 使用 curl 发送请求
    # -s: 静默模式
    # --connect-timeout 5: 5秒连接超时
    # -w "\n%{http_code}": 在输出末尾加上HTTP状态码

    local response
    response=$(curl -G -s --interface "$interface" --connect-timeout 5 -w "\n%{http_code}" "http://10.1.1.1:801/eportal/portal/login" --data-urlencode "user_account=,0,$account@$isp" --data-urlencode "user_password=$password")
    
    # 从响应中分离 body 和 http_code
    local http_code
    http_code=$(echo "$response" | tail -n1)
    local body
    body=$(echo "$response" | sed '$d')

    if [ "$http_code" -ne 200 ]; then
        write_log "$LOG_TAG_AUTH" "认证错误: HTTP状态码为 $http_code"
        write_log "$LOG_TAG_AUTH" "响应内容: $body"
        return 3
    fi

    local json_msg
    json_msg=$(echo "$body" | sed -e "s/.*('//" -e "s/').*//")

    if [ -z "$json_msg" ]; then
        write_log "$LOG_TAG_AUTH" "认证错误: 无法解析响应"
        write_log "$LOG_TAG_AUTH" "完整响应: $body"
        return 4
    fi

    # 使用 grep -q 进行静默检查
    if echo "$body" | grep -q -e '"ret_code":0' -e 'Portal协议认证成功！'; then
        write_log "$LOG_TAG_AUTH" "认证成功"
        write_log "$LOG_TAG_AUTH" "响应: $json_msg"
        touch "/tmp/auth/${interface}_${account}_${isp}"
        return 0
    elif echo "$body" | grep -q '"ret_code":2'; then
        write_log "$LOG_TAG_AUTH" "状态保持 (已在线)"
        write_log "$LOG_TAG_AUTH" "响应: $json_msg"
        touch "/tmp/auth/${interface}_${account}_${isp}"
        return 1
    elif echo "$body" | grep -q '"ret_code":1'; then
        local reason
        reason=$(echo "$json_msg" | grep -oP '(?<="msg":")[^"]+')
        write_log "$LOG_TAG_AUTH" "认证失败: $reason"
        write_log "$LOG_TAG_AUTH" "响应: $json_msg"
        rm -f "/tmp/auth/${interface}_${account}_${isp}"
        #检查body中是否存在特定信息 Max user number exceed 
        if echo "$body" | grep -q 'Max user number exceed'; then
            return 99
        fi
        return 2
    else
        write_log "$LOG_TAG_AUTH" "认证错误: 未知响应"
        write_log "$LOG_TAG_AUTH" "完整响应: $body"
        return 4
    fi
}

# 定义退出前的操作
cleanup() {
    write_log "$LOG_TAG_AUTH" "认证脚本正在退出..."
    write_log "$LOG_TAG_AUTH" "下线设备..."
    local response
    response=$(curl -s --interface "$interface" --data-urlencode "user_account=$account" 'https://10.1.1.1:802/eportal/portal/mac/unbind')
    write_log "$LOG_TAG_AUTH" "下线设备响应: $response"
    rm -f "/tmp/auth/${interface}_${account}_${isp}"
    write_log "$LOG_TAG_AUTH" "退出完成"
}

# ==============================================================================
# Main Logic
# ==============================================================================

# 判断参数有效性

if [ $# -lt 4 ]; then
    echo "Usage: $0 <interface:string> <account:string> <password:string> <isp:[telecomn|unicomn|cmccn]>"
    exit 1
fi

if [ -z "$1" ]; then
    echo "Error: Interface cannot be empty"
    exit 1
fi

if ! ip link show "$1" &>/dev/null; then
    echo "Error: Interface $1 does not exist"
    exit 1
fi

interface="$1"


if [ -z "$2" ] || [ -z "$3" ]; then
    echo "Error: Account and password cannot be empty"
    exit 1
fi

account="$2"
password="$3"


if [ "$4" != "telecomn" ] && [ "$4" != "unicomn" ] && [ "$4" != "cmccn" ]; then
    echo "Error: ISP must be one of [telecomn, unicomn, cmccn]"
    exit 1
fi

isp="$4"

LOG_TAG_CHECK_ONLINE="${interface}-在线状态检查:${account}@${isp}"
LOG_TAG_AUTH="${interface}-校园网认证:${account}@${isp}"

# 创建日志目录
mkdir -p /var/log/auth/
mkdir -p /tmp/auth/
# 重定向标准输出和错误到日志文件
exec >> "/var/log/auth/${interface}_${account}_${isp}_auth.log" 2>&1

# 捕获 EXIT 信号
trap cleanup EXIT
# 捕获 SIGTERM 信号
trap exit SIGTERM
# 捕获 SIGINT 信号 (如 Ctrl+C)
trap exit SIGINT

# 初始化时间戳
last_auth_time=0
last_log_time=0

write_log "$LOG_TAG_AUTH" "认证脚本已启动"

while true; do
    if check_online "$interface"; then
        current_time=$(date +%s)
        # 如果网络正常，并且距离上次打印日志超过 LOG_INTERVAL
        if [ $((current_time - last_log_time)) -ge ${LOG_INTERVAL} ]; then
            write_log "$LOG_TAG_CHECK_ONLINE" "设备已认证，等待下一次检查"
            last_log_time=${current_time}
        fi
        sleep ${ONLINE_CHECK_INTERVAL}
        continue
    fi

    # --- 设备下线，准备认证 ---
    write_log "$LOG_TAG_CHECK_ONLINE" "设备下线，尝试重新认证"
    current_time=$(date +%s)

    # 检查认证冷却时间
    if [ $((current_time - last_auth_time)) -lt ${AUTH_COOLDOWN} ]; then
        write_log "$LOG_TAG_AUTH" "认证操作过于频繁，等待中..."
        sleep ${AUTH_RETRY_INTERVAL}
        continue
    fi

    # 执行认证并更新时间戳
    write_log "$LOG_TAG_AUTH" "======== 开始认证过程 ========"
    authenticate
    auth_result=$?
    write_log "$LOG_TAG_AUTH" "======== 结束认证过程 ========"

    last_auth_time=$(date +%s)
    
    # 认证后稍作等待
    sleep ${AUTH_RETRY_INTERVAL}
done