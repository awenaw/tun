#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <arpa/inet.h>

int tun_alloc(char *dev) {
    struct ifreq ifr;
    int fd, err;

    if ((fd = open("/dev/net/tun", O_RDWR)) < 0) {
        perror("Opening /dev/net/tun");
        return fd;
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    
    if (*dev) {
        strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    }

    if ((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0) {
        perror("ioctl(TUNSETIFF)");
        close(fd);
        return err;
    }

    strcpy(dev, ifr.ifr_name);
    return fd;
}

int main() {
    int tun_fd;
    char tun_name[IFNAMSIZ] = "tun0";
    char buffer[2000];
    int nread;

    // 创建TUN设备
    tun_fd = tun_alloc(tun_name);
    if (tun_fd < 0) {
        perror("Allocating interface");
        exit(1);
    }

    printf("TUN interface %s created successfully\n", tun_name);

    // 读取数据包
    while (1) {
        nread = read(tun_fd, buffer, sizeof(buffer));
        if (nread < 0) {
            perror("Reading from interface");
            close(tun_fd);
            exit(1);
        }

        printf("Read %d bytes from TUN\n", nread);
        
        // 简单回显数据包（实际应用中需要处理IP包）
        if (write(tun_fd, buffer, nread) < 0) {
            perror("Writing to interface");
        }
    }

    return 0;
}