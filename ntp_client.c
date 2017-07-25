// ©.
// https://github.com/sizet/ntp_client

#include <time.h>
#include <errno.h>
#include <stdio.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <setjmp.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>




#define DMSG(msg_fmt, msg_args...) \
    printf("%s(%04u): " msg_fmt "\n", __FILE__, __LINE__, ##msg_args)




#define DEFAULT_NTP_SERVER "time.stdtime.gov.tw"

#define NTP_PORT 123

#define RESOLVE_TIMEOUT 5
#define SEND_TIMEOUT 5
#define RECV_TIMEOUT 5

// NTP  時間是從 1900/01/01-00:00:00 開始.
// UNIX 時間是從 1970/01/01-00:00:00 開始.
// 計算 1900 到 1970 經過的秒數.
#define NTP_1900_TO_1970_SEC 2208988800U

// NTP 紀錄秒的小數部分每單位是 2^-32 秒,
// gettimeofday() 取出的秒的小數部分單位是微秒,
// 微秒轉 NTP 的秒的小數部分的算法 :
// fra  : NTP 紀錄秒的小數部分.
// sec  : 秒.
// usec : 微秒.
// 1. fra = 2^32 * sec
// 2. sec = usec / 10^6
// => fra = 2^32 * (usec / 10^6)
// ** fra = 4294.967296 * usec
// 不使用浮點運算, 改使用整數運算取大概值.
#define NTP_USEC_TO_FRA(usec) ((4294 * (usec)) + ((1981 * (usec)) >> 11))

// NTP 紀錄秒的小數部分轉成微秒.
// usec = fra / 4294.967296
// 不使用浮點運算, 改使用整數運算取大概值.
#define NTP_FRA_TO_USEC(fra) (((fra) >> 12) - (759 * ((((fra) >> 10) + 32768) >> 16)))

// 轉換 delay 和 dispersion 成微秒.
// delay 和 dispersion 是 32bit 資料,
// 高 16bit 表示秒數, 低 16bit 表示秒的小數部分,
// usec = (1000000 * sec) / 65536
// 不使用浮點運算, 改使用整數運算取大概值.
#define NTP_SEC_TO_USEC(sec) ((sec) * 15.2587890625)




struct ntp_ts_t
{
    __u32 sec;
    __u32 fra;
} __attribute__ ((packed));

struct ntp_hdr_t
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
    __u8 mode:3,
         vn:3,
         li:2;
#elif __BYTE_ORDER == __BIG_ENDIAN
    __u8 li:2,
         vn:3,
         mode:3;
#else
#error "please check endian type"
#endif
    __u8 strat;
    __s8 poll;
    __s8 prec;
    __s32 root_delay;
    __u32 root_disp;
    __u32 refn_id;
    struct ntp_ts_t refn_ts;
    struct ntp_ts_t orig_ts;
    struct ntp_ts_t recv_ts;
    struct ntp_ts_t tran_ts;
} __attribute__ ((packed));

union u_addr
{
    struct in_addr addr4;
    struct in6_addr addr6; 
};
struct inx_addr
{
    int af_type;
    union u_addr addr;
};




int shutdown_process = 0;
static sigjmp_buf sigjmp_timeout;




void signal_handle(
    int signal_value)
{
    switch(signal_value)
    {
        case SIGINT:
        case SIGQUIT:
        case SIGTERM:
            shutdown_process = 1;
            break;
        case SIGALRM:
            siglongjmp(sigjmp_timeout, 1);
            break;
    }

    return;
}

int add_pid_file(
    char *file_path)
{
    FILE *file_fp;


    if(file_path != NULL)
    {
        file_fp = fopen(file_path, "w");
        if(file_fp == NULL)
        {
            DMSG("call fopen(%s) fail [%s]", file_path, strerror(errno));
            return -1;
        }
        fprintf(file_fp, "%d", getpid());
        fclose(file_fp);
    }

    return 0;
}

int del_pid_file(
    char *file_path)
{
    if(file_path != NULL)
        if(unlink(file_path) == -1)
        {
            DMSG("call unlink(%s) fail [%s]", file_path, strerror(errno));
            return -1;
        }

    return 0;
}

int get_host_addr(
    char *host_name,
    int addr_family,
    unsigned int resolve_timeout,
    struct inx_addr *host_addr_buf)
{
    int fret = -1, cret;
    struct addrinfo hint, *addr_res, *each_addr;
    char haddr[46];
    void *naddr;


    // 使用 sigsetjmp() 和 SIGALRM 處理回應超時.
    if(resolve_timeout > 0)
    {
        if(sigsetjmp(sigjmp_timeout, 1) != 0)
        {
            DMSG("call getaddrinfo() timeout");
            goto FREE_01;
        }
        signal(SIGALRM, signal_handle);
        alarm(resolve_timeout);
    }

    memset(&hint, 0, sizeof(hint));
    hint.ai_family = addr_family;
    hint.ai_socktype = SOCK_STREAM;
    cret = getaddrinfo(host_name, NULL, &hint, &addr_res);
    if(cret != 0)
    {
        DMSG("call getaddrinfo() fail [%s]", gai_strerror(cret));
        goto FREE_01;
    }

    for(each_addr = addr_res; each_addr != NULL; each_addr = each_addr->ai_next)
        if(each_addr->ai_family == addr_family)
        {
            host_addr_buf->af_type = each_addr->ai_family;
            if(each_addr->ai_family == AF_INET)
            {
                memcpy(&host_addr_buf->addr.addr4,
                       &(((struct sockaddr_in *) each_addr->ai_addr)->sin_addr),
                       sizeof(host_addr_buf->addr.addr4));
            }
            else
            {
                memcpy(&host_addr_buf->addr.addr6,
                       &(((struct sockaddr_in6 *) each_addr->ai_addr)->sin6_addr),
                       sizeof(host_addr_buf->addr.addr6));
            }
            break;
        }
    if(each_addr == NULL)
    {
        DMSG("resolve (%s) fail", host_name);
        goto FREE_02;
    }

    if(host_addr_buf->af_type == AF_INET)
        naddr = &host_addr_buf->addr.addr4;
    else
        naddr = &host_addr_buf->addr.addr6;
    inet_ntop(host_addr_buf->af_type, naddr, haddr, sizeof(haddr));
    DMSG("%s = %s\n", host_name, haddr);

    fret = 0;
FREE_02:
    freeaddrinfo(addr_res);
FREE_01:
    if(resolve_timeout > 0)
    {
        signal(SIGALRM, SIG_IGN);
        alarm(0);
    }
    return fret;
}

int socket_init(
    int addr_family,
    int *sockfd_buf)
{
    int sock_fd;


    sock_fd = socket(addr_family, SOCK_DGRAM, IPPROTO_UDP);
    if(sock_fd == -1)
    {
        DMSG("call socket() fail [%s]", strerror(errno));
        return -1;
    }

    *sockfd_buf = sock_fd;

    return 0;
}

ssize_t socket_sendto(
    int sock_fd,
    void *data_con,
    size_t data_len,
    struct sockaddr *sock_addr,
    socklen_t addr_len,
    unsigned int send_timeout)
{
    int cret;
    fd_set select_set;
    struct timeval select_timeout;
    ssize_t slen;


    FD_ZERO(&select_set);
    FD_SET(sock_fd, &select_set);

    select_timeout.tv_sec = send_timeout;
    select_timeout.tv_usec = 0;

    if(select(sock_fd + 1, NULL, &select_set, NULL, &select_timeout) == -1)
    {
        DMSG("call select() fail [%s]", strerror(errno));
        return -1;
    }

    cret = FD_ISSET(sock_fd, &select_set);
    if(cret == -1)
    {
        DMSG("call FD_ISSET() fail [%s]", strerror(errno));
        return -1;
    }
    if(cret == 0)
        return 0;

    slen = sendto(sock_fd, data_con, data_len, 0, sock_addr, addr_len);
    if(slen != data_len)
    {
        DMSG("call sendto() fail [%zd/%zu] [%s]", slen, data_len, strerror(errno));
        return -1;
    }

    return slen;
}

ssize_t socket_recvfrom(
    int sock_fd,
    void *data_buf,
    size_t buf_size,
    struct sockaddr *sock_addr_buf,
    socklen_t addr_len,
    unsigned int recv_timeout)
{
    int cret;
    fd_set select_set;
    struct timeval select_timeout;
    socklen_t addr_size = addr_len;
    ssize_t rlen;


    FD_ZERO(&select_set);
    FD_SET(sock_fd, &select_set);

    select_timeout.tv_sec = recv_timeout;
    select_timeout.tv_usec = 0;

    if(select(sock_fd + 1, &select_set, NULL, NULL, &select_timeout) == -1)
    {
        DMSG("call select() fail [%s]", strerror(errno));
        return -1;
    }

    cret = FD_ISSET(sock_fd, &select_set);
    if(cret == -1)
    {
        DMSG("call FD_ISSET() fail [%s]", strerror(errno));
        return -1;
    }
    if(cret == 0)
        return 0;

    rlen = recvfrom(sock_fd, data_buf, buf_size, 0, sock_addr_buf, &addr_size);
    if(rlen == -1)
    {
        DMSG("call recvfrom() fail [%s]", strerror(errno));
        return -1;
    }

    return rlen;
}

int fill_ntp_req(
    struct ntp_hdr_t *ntp_hdr,
    struct ntp_ts_t *tran_ts)
{
    struct timeval now_tv;


    // 取得目前的時間.
    gettimeofday(&now_tv, NULL);
    // NTP 的時間是從 1900/01/01-00:00:00 開始, UNIX 時間是從 1970/01/01-00:00:00 開始,
    // 加上 1900 ~ 1970 的差值.
    tran_ts->sec = now_tv.tv_sec + NTP_1900_TO_1970_SEC;
    tran_ts->fra = NTP_USEC_TO_FRA(now_tv.tv_usec);

    ntp_hdr->li = 0;
    ntp_hdr->vn = 3;
    ntp_hdr->mode = 3;
    ntp_hdr->strat = 0;
    ntp_hdr->poll = 4;
    ntp_hdr->prec = -6;
    ntp_hdr->root_delay = htonl(0x1 << 16);
    ntp_hdr->root_disp = htonl(0x1 << 16);
    ntp_hdr->tran_ts.sec = htonl(tran_ts->sec);
    ntp_hdr->tran_ts.fra = htonl(tran_ts->fra);

    DMSG("ntp req\n"
         "Leap Indicator       : %u\n"
         "Version Number       : %u\n"
         "Mode                 : %u\n"
         "Stratum              : %u\n"
         "Poll Interval        : %d\n"
         "Precision            : %d\n"
         "Root Delay           : %.06f\n"
         "Root Dispersion      : %.06f\n"
         "Reference Identifier : 0x%08X\n"
         "Reference Timestamp  : %u.%06u\n"
         "Originate Timestamp  : %u.%06u\n"
         "Receive Timestamp    : %u.%06u\n"
         "Transmit Timestamp   : %u.%06u\n",
         ntp_hdr->li,
         ntp_hdr->vn,
         ntp_hdr->mode,
         ntp_hdr->strat,
         ntp_hdr->poll,
         ntp_hdr->prec,
         NTP_SEC_TO_USEC(ntohl(ntp_hdr->root_delay)),
         NTP_SEC_TO_USEC(ntp_hdr->root_disp),
         ntp_hdr->refn_id,
         ntohl(ntp_hdr->refn_ts.sec), NTP_FRA_TO_USEC(ntohl(ntp_hdr->refn_ts.fra)),
         ntohl(ntp_hdr->orig_ts.sec), NTP_FRA_TO_USEC(ntohl(ntp_hdr->orig_ts.fra)),
         ntohl(ntp_hdr->recv_ts.sec), NTP_FRA_TO_USEC(ntohl(ntp_hdr->recv_ts.fra)),
         ntohl(ntp_hdr->tran_ts.sec), NTP_FRA_TO_USEC(ntohl(ntp_hdr->tran_ts.fra)));

    return 0;
}

int check_ntp_rep(
    struct ntp_hdr_t *ntp_hdr,
    ssize_t hdr_len,
    struct ntp_ts_t *tran_ts)
{
    if(hdr_len != sizeof(struct ntp_hdr_t))
    {
        DMSG("invalid response, size not match (%zd)", hdr_len);
        return -1;
    }

    ntp_hdr->root_delay = ntohl(ntp_hdr->root_delay);
    ntp_hdr->root_disp = ntohl(ntp_hdr->root_disp);
    ntp_hdr->refn_ts.sec = ntohl(ntp_hdr->refn_ts.sec);
    ntp_hdr->refn_ts.fra = ntohl(ntp_hdr->refn_ts.fra);
    ntp_hdr->orig_ts.sec = ntohl(ntp_hdr->orig_ts.sec);
    ntp_hdr->orig_ts.fra = ntohl(ntp_hdr->orig_ts.fra);
    ntp_hdr->recv_ts.sec = ntohl(ntp_hdr->recv_ts.sec);
    ntp_hdr->recv_ts.fra = ntohl(ntp_hdr->recv_ts.fra);
    ntp_hdr->tran_ts.sec = ntohl(ntp_hdr->tran_ts.sec);
    ntp_hdr->tran_ts.fra = ntohl(ntp_hdr->tran_ts.fra);

    DMSG("ntp rep\n"
         "Leap Indicator       : %u\n"
         "Version Number       : %u\n"
         "Mode                 : %u\n"
         "Stratum              : %u\n"
         "Poll Interval        : %d\n"
         "Precision            : %d\n"
         "Root Delay           : %.06f\n"
         "Root Dispersion      : %.06f\n"
         "Reference Identifier : 0x%08X\n"
         "Reference Timestamp  : %u.%06u\n"
         "Originate Timestamp  : %u.%06u\n"
         "Receive Timestamp    : %u.%06u\n"
         "Transmit Timestamp   : %u.%06u\n",
         ntp_hdr->li,
         ntp_hdr->vn,
         ntp_hdr->mode,
         ntp_hdr->strat,
         ntp_hdr->poll,
         ntp_hdr->prec,
         NTP_SEC_TO_USEC(ntohl(ntp_hdr->root_delay)),
         NTP_SEC_TO_USEC(ntp_hdr->root_disp),
         ntp_hdr->refn_id,
         ntp_hdr->refn_ts.sec, NTP_FRA_TO_USEC(ntp_hdr->refn_ts.fra),
         ntp_hdr->orig_ts.sec, NTP_FRA_TO_USEC(ntp_hdr->orig_ts.fra),
         ntp_hdr->recv_ts.sec, NTP_FRA_TO_USEC(ntp_hdr->recv_ts.fra),
         ntp_hdr->tran_ts.sec, NTP_FRA_TO_USEC(ntp_hdr->tran_ts.fra));

    if(ntp_hdr->li == 3)
    {
        DMSG("invalid response, Leap_Indicator");
        return -1;
    }

    if(ntp_hdr->vn < 3)
    {
        DMSG("invalid response, Version_Number");
        return -1;
    }

    if(ntp_hdr->mode != 4)
    {
        DMSG("invalid response, Mode");
        return -1;
    }

    if(ntp_hdr->strat == 0)
    {
        DMSG("invalid response, Stratum");
        return -1;
    }

    if((ntp_hdr->root_delay < -65536) || (65536 < ntp_hdr->root_delay))
    {
        DMSG("invalid response, Root_Delay");
        return -1;
    }

    if(ntp_hdr->root_disp > 65536)
    {
        DMSG("invalid response, Root_Dispersion");
        return -1;
    }

    if((ntp_hdr->orig_ts.sec != tran_ts->sec) ||
       (ntp_hdr->orig_ts.fra != tran_ts->fra))
    {
        DMSG("invalid response, Originate_Timestamp");
        return -1;
    }

    if((ntp_hdr->tran_ts.sec == 0) || (ntp_hdr->tran_ts.fra == 0))
    {
        DMSG("invalid response, Transmit_Timestamp");
        return -1;
    }

    return 0;
}

int update_system_time(
    struct ntp_ts_t *tran_ts)
{
    struct timeval sys_tv, new_tv;
    time_t tmp_time;
    struct tm *tmp_tm;

    gettimeofday(&sys_tv, NULL);
    tmp_time = sys_tv.tv_sec;
    tmp_tm = gmtime(&tmp_time);
    DMSG("system time (UTC) : %04d/%02d/%02d-%02d:%02d:%02d",
         1900 + tmp_tm->tm_year, tmp_tm->tm_mon, tmp_tm->tm_mday,
         tmp_tm->tm_hour, tmp_tm->tm_min, tmp_tm->tm_sec);

    new_tv.tv_sec = tran_ts->sec - NTP_1900_TO_1970_SEC;
    new_tv.tv_usec = NTP_FRA_TO_USEC(tran_ts->fra);
    tmp_time = new_tv.tv_sec;
    tmp_tm = gmtime(&tmp_time);
    DMSG("NTP time    (UTC) : %04d/%02d/%02d-%02d:%02d:%02d\n",
         1900 + tmp_tm->tm_year, tmp_tm->tm_mon, tmp_tm->tm_mday,
         tmp_tm->tm_hour, tmp_tm->tm_min, tmp_tm->tm_sec);

    if(settimeofday(&new_tv, NULL) < 0)
    {
        DMSG("call settimeofday() fail [%s]", strerror(errno));
        return -1;
    }

    return 0;
}

int process_ntp(
    struct inx_addr *server_addr)
{
    int fret = -1, sock_fd;
    struct ntp_hdr_t ntp_hdr;
    struct ntp_ts_t tran_ts;
    struct sockaddr_in sock_addr4;
    struct sockaddr_in6 sock_addr6;
    struct sockaddr *sock_addrx;
    socklen_t addr_len;
    ssize_t rlen;


    if(server_addr->af_type == AF_INET)
    {
        memset(&sock_addr4, 0, sizeof(sock_addr4));
        sock_addr4.sin_family = AF_INET;
        sock_addr4.sin_port = htons(NTP_PORT);
        memcpy(&sock_addr4.sin_addr, &server_addr->addr.addr4, sizeof(sock_addr4.sin_addr));
        sock_addrx = (struct sockaddr *) &sock_addr4;
        addr_len = sizeof(sock_addr4);
    }
    else
    {
        memset(&sock_addr6, 0, sizeof(sock_addr6));
        sock_addr6.sin6_family = AF_INET6;
        sock_addr6.sin6_port = htons(NTP_PORT);
        memcpy(&sock_addr6.sin6_addr, &server_addr->addr.addr6, sizeof(sock_addr6.sin6_addr));
        sock_addrx = (struct sockaddr *) &sock_addr6;
        addr_len = sizeof(sock_addr6);
    }

    if(socket_init(server_addr->af_type, &sock_fd) < 0)
    {
        DMSG("call socket_init() fail");
        goto FREE_01;
    }

    memset(&ntp_hdr, 0, sizeof(ntp_hdr));
    memset(&tran_ts, 0, sizeof(tran_ts));
    fill_ntp_req(&ntp_hdr, &tran_ts);

    if(socket_sendto(sock_fd, &ntp_hdr, sizeof(ntp_hdr), sock_addrx, addr_len, SEND_TIMEOUT) < 0)
    {
        DMSG("call socket_sendto() fail");
        goto FREE_02;
    }

    rlen = socket_recvfrom(sock_fd, &ntp_hdr, sizeof(ntp_hdr), sock_addrx, addr_len, RECV_TIMEOUT);
    if(rlen < 0)
    {
        DMSG("call socket_recvfrom() fail");
        goto FREE_02;
    }

    if(check_ntp_rep(&ntp_hdr, rlen, &tran_ts) < 0)
    {
        DMSG("call check_ntp_rep() fail");
        goto FREE_02;
    }

    if(update_system_time(&ntp_hdr.tran_ts) < 0)
    {
        DMSG("call update_system_time() fail");
        goto FREE_02;
    }

    fret = 0;
FREE_02:
    close(sock_fd);
FREE_01:
    return fret;
}

int main(
    int argc,
    char **argv)
{
    char opt_ch, *server_host = DEFAULT_NTP_SERVER, *pid_path = NULL;
    unsigned int update_interval = 0;
    int addr_family = AF_INET;
    struct inx_addr server_addr;


    while((opt_ch = getopt(argc , argv, "s:u:a:p:"))!= -1)
    {
        switch(opt_ch)
        {
            case 's':
                server_host = optarg;
                break;
            case 'u':
                update_interval = strtoul(optarg, NULL, 10);
                break;
            case 'a':
                if(optarg[0] == '4')
                {
                    addr_family = AF_INET;
                }
                else
                if(optarg[0] == '6')
                {
                    addr_family = AF_INET6;
                }
                else
                {
                    DMSG("invalid address family");
                    goto FREE_HELP;
                }
                break;
            case 'p':
                pid_path = optarg;
                break;
            default:
                goto FREE_HELP;
        }
    }

    signal(SIGINT, signal_handle);
    signal(SIGQUIT, signal_handle);
    signal(SIGTERM, signal_handle);

    memset(&server_addr, 0, sizeof(server_addr));
    if(get_host_addr(server_host, addr_family, RESOLVE_TIMEOUT, &server_addr) < 0)
    {
        DMSG("call get_host_addr() fail");
        goto FREE_01;
    }

    if(add_pid_file(pid_path) < 0)
    {
        DMSG("call get_host_addr() fail");
        goto FREE_01;
    }

    while(shutdown_process == 0)
    {
        if(process_ntp(&server_addr) < 0)
        {
            DMSG("call process_ntp() fail");
            goto FREE_02;
        }

        if(update_interval != 0)
        {
            DMSG("next update, %u second", update_interval);
            sleep(update_interval);
        }
        else
        {
            break;
        }
    }

FREE_02:
    del_pid_file(pid_path);
FREE_01:
    return 0;
FREE_HELP:
    printf("\nntp_client [-s] [-u] [-a] [-p]\n");
    printf("  -s : NTP server domain name\n");
    printf("       ex : -s clock.stdtime.gov.tw, default = %s\n", DEFAULT_NTP_SERVER);
    printf("  -u : update interval (seconds)\n");
    printf("       0 = run once, large 0 = keep update\n");
    printf("       ex : -u 3600\n");
    printf("  -a : use IPv6 or IPv6\n");
    printf("       4 = use IPv4 protocol, 6 = use IPv6 protocol, default = IPv4\n");
    printf("       ex : -a 4\n");
    printf("  -p : file path for save process id\n");
    printf("       ex : -p /var/run/ntp_client.pid\n\n");
    return 0;
}
