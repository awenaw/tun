#include <stdio.h>          // 标准输入输出函数
#include <stdlib.h>         // 标准库函数 (exit, malloc等)
#include <string.h>         // 字符串操作函数 (memset, strcpy等)
#include <unistd.h>         // UNIX标准函数 (read, write, close等)
#include <fcntl.h>          // 文件控制函数 (open, O_RDWR等)
#include <sys/ioctl.h>      // 设备控制函数 (ioctl)
#include <linux/if.h>       // 网络接口相关结构体和常量
#include <linux/if_tun.h>   // TUN/TAP设备相关定义
#include <arpa/inet.h>      // 网络地址转换函数

/**
 * 创建并配置TUN网络接口
 * @param dev 设备名称，如果为空则由系统自动分配
 * @return 成功返回TUN设备的文件描述符，失败返回负数
 */
int tun_alloc(char *dev) {
    struct ifreq ifr;       // 网络接口请求结构体
    int fd, err;            // 文件描述符和错误码
    
    // 打开TUN/TAP设备文件，这是Linux提供的虚拟网络设备接口
    // O_RDWR表示以读写方式打开
    if ((fd = open("/dev/net/tun", O_RDWR)) < 0) {
        perror("Opening /dev/net/tun");  // 打印错误信息
        return fd;
    }
    
    // 清零接口请求结构体，确保没有垃圾数据
    memset(&ifr, 0, sizeof(ifr));
    
    // 设置接口标志位
    // IFF_TUN: 创建TUN设备（处理IP层数据包，而非TAP的以太网帧）
    // IFF_NO_PI: 不包含包信息头，直接处理IP数据包
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    
    // 如果指定了设备名称，则复制到请求结构体中
    // IFNAMSIZ是接口名称的最大长度（通常是16字节）
    if (*dev) {
        strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    }
    
    // 通过ioctl系统调用创建TUN接口
    // TUNSETIFF是创建TUN/TAP接口的ioctl命令
    if ((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0) {
        perror("ioctl(TUNSETIFF)");     // 打印错误信息
        close(fd);                       // 关闭文件描述符
        return err;
    }
    
    // 将系统分配的实际设备名称复制回dev参数
    // 这样调用者就能知道创建的接口名称
    strcpy(dev, ifr.ifr_name);
    
    return fd;  // 返回TUN设备的文件描述符
}

int main() {
    int tun_fd;                         // TUN设备的文件描述符
    char tun_name[IFNAMSIZ] = "tun0";   // 期望的TUN设备名称
    char buffer[2000];                  // 数据包缓冲区（2000字节足够容纳大部分IP包）
    int nread;                          // 实际读取的字节数
    
    // 创建TUN设备
    tun_fd = tun_alloc(tun_name);
    if (tun_fd < 0) {
        perror("Allocating interface");  // 打印错误信息
        exit(1);                         // 程序异常退出
    }
    
    printf("TUN interface %s created successfully\n", tun_name);
    
    // 主循环：持续读取和处理数据包
    while (1) {
        // 从TUN接口读取IP数据包
        // 当有数据包被路由到这个TUN接口时，read会返回
        nread = read(tun_fd, buffer, sizeof(buffer));
        
        if (nread < 0) {
            perror("Reading from interface"); // 读取出错
            close(tun_fd);                     // 清理资源
            exit(1);
        }
        
        printf("Read %d bytes from TUN\n", nread);
        
        // 简单回显数据包（将读取的数据包原样写回TUN接口）
        // 注意：这只是演示代码，实际应用中需要：
        // 1. 解析IP包头
        // 2. 根据目标地址进行路由决策
        // 3. 可能需要加密/解密处理
        // 4. 转发到正确的目的地
        if (write(tun_fd, buffer, nread) < 0) {
            perror("Writing to interface");
        }
        
        // 在真实的VPN实现中，这里应该是：
        // 1. 解析接收到的IP数据包
        // 2. 根据VPN配置决定如何处理（加密、路由等）
        // 3. 通过UDP socket发送到VPN对端
        // 4. 或者从UDP socket接收加密数据，解密后写入TUN
    }
    
    // 程序正常结束时的清理（实际上这里永远不会执行到）
    close(tun_fd);
    return 0;
}