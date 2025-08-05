/*
 * WireGuard UDP通信概念演示
 * 展示WireGuard如何通过UDP与对端通信的基本原理
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>

#define WG_DEFAULT_PORT 51820
#define BUFFER_SIZE 2000

// 模拟WireGuard数据包结构
struct wg_packet {
    uint8_t type;           // 1=握手, 4=数据包
    uint8_t reserved[3];    
    uint32_t session_id;    // 会话ID
    uint64_t counter;       // 数据包计数器
    uint8_t data[];         // 加密的IP数据包
} __attribute__((packed));

// WireGuard对等节点信息
struct wg_peer {
    struct sockaddr_in endpoint;  // 对端UDP地址
    uint32_t session_id;          // 当前会话ID
    uint64_t tx_counter;          // 发送计数器
    uint64_t rx_counter;          // 接收计数器
};

/**
 * 创建UDP socket用于与WireGuard对端通信
 */
int create_wg_socket(int port) {
    int sockfd;
    struct sockaddr_in addr;
    
    // 创建UDP socket
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("创建UDP socket失败");
        return -1;
    }
    
    // 绑定到指定端口
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    
    if (bind(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("绑定端口失败");
        close(sockfd);
        return -1;
    }
    
    printf("✓ UDP socket创建成功，监听端口 %d\n", port);
    return sockfd;
}

/**
 * 模拟发送数据包到WireGuard对端
 */
int send_to_peer(int sockfd, struct wg_peer *peer, const void *data, size_t len) {
    struct wg_packet *pkt;
    size_t total_len = sizeof(struct wg_packet) + len;
    
    // 分配数据包内存
    pkt = malloc(total_len);
    if (!pkt) return -1;
    
    // 构造WireGuard数据包
    pkt->type = 4;  // 数据包类型
    memset(pkt->reserved, 0, 3);
    pkt->session_id = peer->session_id;
    pkt->counter = ++peer->tx_counter;
    
    // 在真实WireGuard中，这里会进行ChaCha20+Poly1305加密
    memcpy(pkt->data, data, len);
    
    // 通过UDP发送到对端
    ssize_t sent = sendto(sockfd, pkt, total_len, 0, 
                         (struct sockaddr*)&peer->endpoint, 
                         sizeof(peer->endpoint));
    
    if (sent > 0) {
        printf("→ 发送 %zd 字节到 %s:%d (计数器: %lu)\n", 
               sent, inet_ntoa(peer->endpoint.sin_addr), 
               ntohs(peer->endpoint.sin_port), pkt->counter);
    }
    
    free(pkt);
    return sent > 0 ? 0 : -1;
}

/**
 * 模拟从WireGuard对端接收数据包
 */
int receive_from_peer(int sockfd, void *buffer, size_t buffer_size) {
    struct sockaddr_in from_addr;
    socklen_t from_len = sizeof(from_addr);
    
    ssize_t received = recvfrom(sockfd, buffer, buffer_size, 0,
                               (struct sockaddr*)&from_addr, &from_len);
    
    if (received > 0) {
        struct wg_packet *pkt = (struct wg_packet*)buffer;
        
        printf("← 接收 %zd 字节来自 %s:%d\n", 
               received, inet_ntoa(from_addr.sin_addr), 
               ntohs(from_addr.sin_port));
        
        if (received >= sizeof(struct wg_packet)) {
            printf("  数据包类型: %d, 会话ID: %u, 计数器: %lu\n",
                   pkt->type, pkt->session_id, pkt->counter);
            
            // 在真实WireGuard中，这里会进行解密
            size_t data_len = received - sizeof(struct wg_packet);
            if (data_len > 0) {
                printf("  载荷数据: %zu 字节\n", data_len);
                return data_len;
            }
        }
    }
    
    return received;
}

/**
 * WireGuard式的心跳保持连接
 */
void *keepalive_thread(void *arg) {
    struct wg_peer *peer = (struct wg_peer*)arg;
    int sockfd = create_wg_socket(0);  // 随机端口
    
    if (sockfd < 0) return NULL;
    
    while (1) {
        // 发送心跳包（空数据包）
        send_to_peer(sockfd, peer, "", 0);
        
        printf("💗 发送心跳到对端\n");
        sleep(25);  // WireGuard默认25秒心跳
    }
    
    close(sockfd);
    return NULL;
}

/**
 * 演示WireGuard UDP通信概念
 */
void demonstrate_wireguard_udp() {
    printf("=== WireGuard UDP通信概念演示 ===\n\n");
    
    // 1. 创建用于监听的UDP socket
    int listen_sockfd = create_wg_socket(WG_DEFAULT_PORT);
    if (listen_sockfd < 0) {
        printf("无法创建监听socket，可能需要sudo权限\n");
        return;
    }
    
    // 2. 配置对等节点信息
    struct wg_peer peer = {
        .endpoint = {
            .sin_family = AF_INET,
            .sin_port = htons(51821),  // 对端端口
            .sin_addr.s_addr = inet_addr("127.0.0.1")  // 本地测试
        },
        .session_id = 12345,
        .tx_counter = 0,
        .rx_counter = 0
    };
    
    printf("配置对端: %s:%d\n\n", 
           inet_ntoa(peer.endpoint.sin_addr),
           ntohs(peer.endpoint.sin_port));
    
    // 3. 模拟发送IP数据包
    printf("--- 模拟数据传输 ---\n");
    char ip_packet[] = "模拟的IP数据包内容";
    send_to_peer(listen_sockfd, &peer, ip_packet, strlen(ip_packet));
    
    // 4. 监听接收数据包
    printf("\n--- 监听接收数据 ---\n");
    printf("监听 UDP 端口 %d，等待数据包...\n", WG_DEFAULT_PORT);
    printf("(可以用 'nc -u localhost %d' 测试发送数据)\n\n", WG_DEFAULT_PORT);
    
    char buffer[BUFFER_SIZE];
    for (int i = 0; i < 3; i++) {  // 只接收3个包作为演示
        fd_set readfds;
        struct timeval timeout = {5, 0};  // 5秒超时
        
        FD_ZERO(&readfds);
        FD_SET(listen_sockfd, &readfds);
        
        int activity = select(listen_sockfd + 1, &readfds, NULL, NULL, &timeout);
        if (activity > 0) {
            receive_from_peer(listen_sockfd, buffer, sizeof(buffer));
        } else {
            printf("超时，没有收到数据包\n");
        }
    }
    
    close(listen_sockfd);
    
    printf("\n=== 关键要点 ===\n");
    printf("1. WireGuard使用UDP作为传输协议\n");
    printf("2. 每个数据包都有计数器防重放攻击\n");
    printf("3. 通过心跳维持NAT映射\n");
    printf("4. 无状态设计，连接恢复简单\n");
    printf("5. 加密在应用层完成（本例中省略）\n");
}

int main() {
    demonstrate_wireguard_udp();
    return 0;
}