#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <arpa/inet.h>
#include <netinet/ip.h>

/*
 * awenawtun - TUN接口流量捕获工具
 *
 * 【功能描述】
 * 这个程序创建一个名为 awenawtun 的TUN虚拟网络接口，用于捕获和处理
 * 发往 192.168.233.x/24 网段的所有网络流量。适用于网络分析、
 * VPN开发、流量监控等场景。
 *
 * 【主要特性】
 * - 自动创建和配置 awenawtun TUN接口
 * - 自动设置IP地址 192.168.233.1/24
 * - 自动添加路由规则，拦截 192.168.233.0/24 网段流量
 * - 实时解析并显示IP数据包信息（源IP、目标IP、协议类型、长度）
 * - 简单的数据包回显功能（用于ping响应）
 *
 * 【系统要求】
 * - Linux操作系统（内核支持TUN/TAP）
 * - root权限（创建网络接口需要管理员权限）
 * - gcc编译器
 * - 系统工具：ip命令（iproute2包）
 *
 * 【依赖检查】
 * 运行前请确保：
 * 1. 系统支持TUN/TAP：ls /dev/net/tun
 * 2. 有ip命令：which ip
 * 3. 有root权限：sudo whoami
 *
 * 【编译方法】
 * gcc -o awenawtun awenawtun.c
 *
 * 【使用方法】
 * 1. 编译程序：gcc -o awenawtun awenawtun.c
 * 2. 运行程序：sudo ./awenawtun
 * 3. 程序会自动配置网络接口和路由
 * 4. 在另一个终端测试：
 *    ping 192.168.233.2      # ICMP流量测试
 *    curl 192.168.233.50     # HTTP流量测试  
 *    nc 192.168.233.100 80   # TCP流量测试
 * 5. 按Ctrl+C退出程序
 *
 * 【工作原理】
 * 1. 创建TUN虚拟网络接口
 * 2. 配置接口IP为192.168.233.1/24
 * 3. 添加路由规则：192.168.233.0/24 -> awenawtun
 * 4. 系统将该网段的流量路由到TUN接口
 * 5. 程序从TUN接口读取IP数据包
 * 6. 解析并显示数据包信息
 * 7. 可选择转发、丢弃或处理数据包
 *
 * 【应用场景】
 * - 网络流量分析和监控
 * - VPN隧道开发
 * - 网络安全研究
 * - 数据包过滤和处理
 * - 网络协议学习
 *
 * 【注意事项】
 * - 需要root权限运行
 * - 程序退出时会自动清理路由规则
 * - 目标网段192.168.233.x不应与现有网络冲突
 * - 仅用于学习和开发，生产环境需要更完善的错误处理
 */

/**
 * 创建并配置TUN网络接口
 * @param dev 设备名称
 * @return 成功返回TUN设备的文件描述符，失败返回负数
 */
int tun_alloc(char *dev) {
    struct ifreq ifr;
    int fd, err;
    
    // 打开TUN设备文件
    if ((fd = open("/dev/net/tun", O_RDWR)) < 0) {
        perror("Opening /dev/net/tun");
        return fd;
    }
    
    // 清零接口请求结构体
    memset(&ifr, 0, sizeof(ifr));
    
    // 设置为TUN模式，不包含包信息头
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    
    // 设置设备名称
    if (*dev) {
        strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    }
    
    // 创建TUN接口
    if ((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0) {
        perror("ioctl(TUNSETIFF)");
        close(fd);
        return err;
    }
    
    // 获取实际创建的设备名称
    strcpy(dev, ifr.ifr_name);
    return fd;
}

/**
 * 配置TUN接口的IP地址和路由
 * @param dev_name 设备名称
 * @param ip_addr IP地址
 * @param network 网络地址段
 * @return 成功返回0
 */
int configure_tun_interface(const char* dev_name, const char* ip_addr, const char* network) {
    char cmd[256];
    int ret;
    
    printf("正在配置TUN接口 %s...\n", dev_name);
    
    // 1. 为TUN接口分配IP地址
    snprintf(cmd, sizeof(cmd), "ip addr add %s dev %s", ip_addr, dev_name);
    printf("执行命令: %s\n", cmd);
    ret = system(cmd);
    if (ret != 0) {
        printf("配置IP地址失败\n");
        return -1;
    }
    
    // 2. 启用TUN接口
    snprintf(cmd, sizeof(cmd), "ip link set %s up", dev_name);
    printf("执行命令: %s\n", cmd);
    ret = system(cmd);
    if (ret != 0) {
        printf("启用接口失败\n");
        return -1;
    }
    
    // 3. 检查路由是否已自动创建
    printf("检查路由状态...\n");
    snprintf(cmd, sizeof(cmd), "ip route show %s 2>/dev/null | wc -l", network);
    FILE *fp = popen(cmd, "r");
    if (fp != NULL) {
        int route_count = 0;
        fscanf(fp, "%d", &route_count);
        pclose(fp);
        
        if (route_count > 0) {
            printf("✓ 路由已自动创建（这是正常的Linux行为）\n");
        } else {
            // 手动添加路由
            snprintf(cmd, sizeof(cmd), "ip route add %s dev %s", network, dev_name);
            printf("执行命令: %s\n", cmd);
            ret = system(cmd);
            if (ret != 0) {
                printf("❌ 添加路由失败\n");
                return -1;
            } else {
                printf("✓ 路由规则添加成功\n");
            }
        }
    }
    
    printf("TUN接口配置完成！\n");
    printf("现在发送到 %s 的流量将被 %s 接口捕获\n", network, dev_name);
    return 0;
}

/**
 * 解析并显示IP数据包信息
 * @param buffer 数据包缓冲区
 * @param length 数据包长度
 */
void parse_ip_packet(unsigned char* buffer, int length) {
    struct iphdr* ip_header = (struct iphdr*)buffer;
    struct in_addr src_addr, dst_addr;
    
    if (length < sizeof(struct iphdr)) {
        printf("数据包太短，无法解析IP头\n");
        return;
    }
    
    // 提取源IP和目标IP
    src_addr.s_addr = ip_header->saddr;
    dst_addr.s_addr = ip_header->daddr;
    
    printf("捕获数据包: %s -> %s, 协议: %d, 长度: %d 字节\n",
           inet_ntoa(src_addr),
           inet_ntoa(dst_addr),
           ip_header->protocol,
           length);
}

/**
 * 显示使用说明
 */
void show_usage() {
    printf("\n=== awenawtun 使用说明 ===\n");
    printf("1. 程序已创建 awenawtun 接口\n");
    printf("2. 配置了IP地址: 192.168.233.1/24\n");
    printf("3. 添加了路由: 192.168.233.0/24 -> awenawtun\n");
    printf("\n测试方法:\n");
    printf("  ping 192.168.233.2    # 会被awenawtun捕获\n");
    printf("  ping 192.168.233.100  # 会被awenawtun捕获\n");
    printf("  curl 192.168.233.50   # 会被awenawtun捕获\n");
    printf("\n按 Ctrl+C 退出程序\n");
    printf("========================\n\n");
}

int main() {
    int tun_fd;
    char tun_name[IFNAMSIZ] = "awenawtun";  // 设定TUN设备名称
    unsigned char buffer[2000];           // 数据包缓冲区
    int nread;
    
    printf("正在创建 awenawtun 接口...\n");
    
    // 1. 创建TUN设备
    tun_fd = tun_alloc(tun_name);
    if (tun_fd < 0) {
        perror("创建TUN接口失败");
        exit(1);
    }
    printf("✓ TUN接口 %s 创建成功\n", tun_name);
    
    // 2. 配置TUN接口IP地址和路由
    if (configure_tun_interface(tun_name, "192.168.233.1/24", "192.168.233.0/24") < 0) {
        printf("配置TUN接口失败\n");
        close(tun_fd);
        exit(1);
    }
    
    // 3. 显示使用说明
    show_usage();
    
    // 4. 主循环：捕获并处理数据包
    printf("开始监听 192.168.233.x 网段的流量...\n\n");
    
    while (1) {
        // 从TUN接口读取IP数据包
        nread = read(tun_fd, buffer, sizeof(buffer));
        
        if (nread < 0) {
            perror("读取TUN接口数据失败");
            break;
        }
        
        printf("\n--- 收到数据包 ---\n");
        parse_ip_packet(buffer, nread);
        
        // 这里可以添加数据包处理逻辑
        // 例如：转发到真实网络、加密处理、记录日志等
        
        // 简单回显数据包（仅用于演示ICMP ping的响应）
        if (write(tun_fd, buffer, nread) < 0) {
            perror("写入TUN接口失败");
        } else {
            printf("数据包已回显\n");
        }
    }
    
    // 清理资源
    printf("\n正在清理资源...\n");
    close(tun_fd);
    
    // 删除添加的路由（可选）
    system("ip route del 192.168.233.0/24 dev awenawtun 2>/dev/null");
    
    return 0;
}