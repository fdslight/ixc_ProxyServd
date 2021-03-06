#include<string.h>
#include<arpa/inet.h>
#include<sys/time.h>

#include "tcp.h"
#include "debug.h"
#include "ip.h"
#include "ipv6.h"
#include "ip2socks.h"

#include "../../../pywind/clib/netutils.h"
#include "../../../pywind/clib/sysloop.h"


static struct tcp_sessions tcp_sessions;
static struct sysloop *tcp_sysloop=NULL;

static void tcp_send_from_buf(struct tcp_session *session);
static void tcp_session_del_cb(void *data);
static void tcp_send_data(struct tcp_session *session,unsigned short status,void *opt,size_t opt_size,void *data,size_t data_size);
static void tcp_session_fin_wait_set(struct tcp_session *session);
static void tcp_send_rst(struct tcp_session *session);

static void tcp_sysloop_cb(struct sysloop *loop)
{
    tcp_timer_do();
}

/// 获取数据传输延迟,单位是ms
static time_t tcp_session_get_data_delay(struct tcp_session *session)
{
    struct timeval now_time;
    time_t delay;
    
    gettimeofday(&now_time,NULL);

    delay=tcp_timer_interval_calc(&(session->data_time_up),&now_time)/1.5;

    if(delay<TCP_TIMER_TICK_INTERVAL) delay=TCP_TIMER_TICK_INTERVAL;

    return delay;
}

static void tcp_session_close(struct tcp_session *session)
{
    struct map *map=session->is_ipv6?tcp_sessions.sessions6:tcp_sessions.sessions;

    map_del(map,(char *)session->id,tcp_session_del_cb);
}

static void tcp_session_fin_wait_set(struct tcp_session *session)
{
    //struct tcp_timer_node *tm_node=session->tm_node;
    session->tcp_st=TCP_ST_FIN_SND_WAIT;

    // 注意一定需要判断语句,需要超时才能更新
    //if(session->tm_node->timeout_flags) tcp_timer_update(tm_node,session->delay_ms);
}

static void tcp_session_del_cb(void *data)
{
    struct tcp_session *session=data;
    
    // 发送一次RST数据包,确保TCP被停止
    tcp_send_rst(session);
    netpkt_tcp_close_ev(session->id,session->is_ipv6);

    if(NULL!=session->data_tm_node) tcp_timer_del(session->data_tm_node);
    if(NULL!=session->conn_tm_node) tcp_timer_del(session->conn_tm_node);

    tcp_sessions.conn_count-=1;

    free(session);
}

static void tcp_session_data_timeout_cb(void *data)
{
    struct tcp_session *session=data;
    struct tcp_timer_node *tm_node=session->data_tm_node;

    // 如果发送缓冲区有数据那么发送数据
    if(TCP_SENT_BUF(session)->used_size!=0 && !session->my_sent_closed){
        //DBG_FLAGS;
        tcp_send_from_buf(session);
        tcp_timer_update(tm_node,session->delay_ms);
    }
}

static void tcp_session_conn_timeout_cb(void *data)
{
    struct tcp_session *session=data;
    struct timeval now_time;
    time_t timeout;

    gettimeofday(&now_time,NULL);

    timeout=tcp_timer_interval_calc(&(session->conn_time_up),&now_time)/1000;

    //DBG_FLAGS;

    // 注意这段if代码要在最开始的位置
    if(session->tcp_st==TCP_ST_FIN_SND_WAIT || session->peer_sent_closed){
        //DBG_FLAGS;
        if(timeout>TCP_TIMEOUT_FIN){
            DBG("TCP fin timeout\r\n");
            tcp_session_close(session);
            return;
        }
        //DBG_FLAGS;
        tcp_timer_update(session->conn_tm_node,1000);
        return;
    }
    
    //DBG_FLAGS;
    if(session->tcp_st==TCP_ST_OK){
        if(timeout>=TCP_TIMEOUT_KEEP_ALIVE){
            DBG("TCP Keep alive timeout\r\n");
            tcp_session_close(session);
            return;
        }
        //DBG_FLAGS;
        tcp_timer_update(session->conn_tm_node,1000);
        return;
    }

    //DBG_FLAGS;
    if(session->tcp_st==TCP_ST_SYN_SND){
        if(timeout>TCP_TIMEOUT_SYN){
            DBG("TCP syn wait timeout\r\n");
            tcp_session_close(session);
            return;
        }
        //DBG_FLAGS;
        tcp_timer_update(session->conn_tm_node,1000);
        return;
    }

    tcp_session_close(session);
}

/// 处理TCP头部选项
// opt_data为选项数据
// opt_len为选项长度
static void tcp_session_handle_header_opt(struct tcp_session *session,void *opt_data,int opt_len)
{
    int kind,length;
    unsigned char *s=opt_data;
    unsigned short mss=0;

    for(int n=0;n<opt_len;){
        kind=s[n];
        if(0==kind) break;
        if(1==kind){
            n++;
            break;
        }
        // 错误的头部长度那么忽略
        if(n+1>=opt_len) break;
        length=s[n+1];
        if(2==kind){
            // 检查长度是否合法
            if(length!=4) break;
            // 防止内存越界
            if(n+4>opt_len) break;
            memcpy(&mss,&s[n+2],2);
            session->peer_mss=ntohs(mss);
        }
        n+=length;
    }

    //DBG("%d\r\n",session->peer_mss);
}

/// 发送TCP错误
static void tcp_send_rst(struct tcp_session *session)
{
    tcp_send_data(session,TCP_RST,NULL,0,NULL,0);
}

static struct tcp_session *tcp_session_get(unsigned char *id,int is_ipv6)
{
    struct map *m=is_ipv6?tcp_sessions.sessions6:tcp_sessions.sessions;
    struct tcp_session *session;
    char is_found;

    session=map_find(m,(char *)id,&is_found);

    return session;
}

/// 构建TCP选项
// kinds[]如果有索引为0代表结束
// return函数返回结果长度,如果小于0代表发生错误,比如参数值不符合规范
static int tcp_build_opts(unsigned char kinds[],void **values[],unsigned char value_lenths[],void *result)
{
    unsigned char kind;
    int tot_len=0;
    unsigned char *opt=result,length;

    for(int i=0;;i++){
        kind=kinds[i];
        tot_len+=1;
        *opt=kind;
        opt++;

        if(kind==0) break;
        if(kind==1) continue;
        
        tot_len+=1;
        length=value_lenths[i];
        *opt=length+2;
        opt++;
        memcpy(opt,values[i],length);
        opt+=length;
        tot_len+=length;
    }   

    return tot_len;
}

/// 发送TCP数据
static void tcp_send_data(struct tcp_session *session,unsigned short status,void *opt,size_t opt_size,void *data,size_t data_size)
{
    struct netutil_ip6_ps_header *ps6_hdr;
    struct netutil_ip_ps_header *ps_hdr;
    struct netutil_tcphdr *tcphdr;
    unsigned short csum;
    struct mbuf *m=mbuf_get();
    unsigned short hdr_len=20+opt_size;

    if(NULL==m){
        STDERR("cannot get mbuf\r\n");
        return;
    }

    m->begin=MBUF_BEGIN;
    m->offset=m->begin;
    m->tail=MBUF_BEGIN+hdr_len+data_size;
    m->end=m->tail;

    tcphdr=(struct netutil_tcphdr *)(m->data+m->begin);
    bzero(tcphdr,hdr_len);

    // 计算检验和必须为2的倍数,如果长度为奇数,那么需要填充后一位为0补齐
    if(data_size % 2!=0) *(m->data+m->tail+1)='\0';
    
    // 源端口和目标端口要对调
    tcphdr->src_port=htons(session->dport);
    tcphdr->dst_port=htons(session->sport);

    // 发送本端的序列号
    tcphdr->seq_num=htonl(session->seq);
    tcphdr->ack_num=htonl(session->peer_seq);
    
    tcphdr->header_len_and_flag=htons(((hdr_len/4)<<12) | status);
    tcphdr->win_size=htons(session->my_window_size);

    memcpy(m->data+m->begin+20,opt,opt_size);
    memcpy(m->data+m->begin+hdr_len,data,data_size);

    data_size+=hdr_len;

    // TCP伪头部处理
    if(session->is_ipv6){
        ps6_hdr=(struct netutil_ip6_ps_header *)(m->data+m->begin-40);
        bzero(ps6_hdr,40);

        memcpy(ps6_hdr->src_addr,session->src_addr,16);
        memcpy(ps6_hdr->dst_addr,session->dst_addr,16);

        ps6_hdr->length=htons(data_size);
        ps6_hdr->next_header=6;

        csum=csum_calc((unsigned short *)(m->data+m->begin-40),m->end-m->begin+40);
    }else{
        ps_hdr=(struct netutil_ip_ps_header *)(m->data+m->begin-12);
        bzero(ps_hdr,12);

        memcpy(ps_hdr->src_addr,session->src_addr,4);
        memcpy(ps_hdr->dst_addr,session->dst_addr,4);

        ps_hdr->length=htons(data_size);
        ps_hdr->protocol=6;

        csum=csum_calc((unsigned short *)(m->data+m->begin-12),m->end-m->begin+12);
    }

    tcphdr->csum=csum;

    if(session->is_ipv6) ipv6_send(session->dst_addr,session->src_addr,6,m->data+m->begin,m->end-m->begin);
    else ip_send(session->dst_addr,session->src_addr,6,m->data+m->begin,m->end-m->begin);

    mbuf_put(m);
}

static void tcp_session_syn(const char *session_id,unsigned char *saddr,unsigned char *daddr,struct netutil_tcphdr *tcphdr,int hdr_len,int is_ipv6,struct mbuf *m)
{
    struct tcp_session *session=NULL;
    struct map *map=is_ipv6?tcp_sessions.sessions6:tcp_sessions.sessions;
    unsigned short my_mss=0;
    char is_found;
    int rs;
    unsigned char opt_kinds[]={
        2,1,1,1,0
    };
    void **opt_values[]={
        (void *)(&my_mss),NULL,NULL
    };
    unsigned char opt_lenths[]={
        2,0,0,0,0
    };
    unsigned char buf[1024];

    session=map_find(map,session_id,&is_found);

    if(NULL==session){
        session=malloc(sizeof(struct tcp_session));
        if(NULL==session){
            STDERR("cannot malloc tcp session\r\n");
            mbuf_put(m);
            return;
        }
        bzero(session,sizeof(struct tcp_session));
        rs=map_add(map,session_id,session);
        if(0!=rs){
            STDERR("cannot add to map for tcp syn\r\n");
            free(session);
            mbuf_put(m);
            return;
        }

        gettimeofday(&(session->conn_time_up),NULL);
        session->conn_tm_node=tcp_timer_add(1000,tcp_session_conn_timeout_cb,session);
        
        if(NULL==session->conn_tm_node){
            STDERR("cannot add to tcp timer\r\n");
            map_del(map,session_id,NULL);
            free(session);
            mbuf_put(m);
            return;
        }

        tcp_buf_init(TCP_SENT_BUF(session));
        session->tcp_st=TCP_ST_SYN_SND;
        session->my_mss=is_ipv6?tcp_sessions.ip6_mss:tcp_sessions.ip_mss;
        
        tcp_sessions.conn_count+=1;
    }else{
        // 如果不是SYN_SND状态则忽略该SYN数据包
        if(session->tcp_st!=TCP_ST_SYN_SND) return;
    }

    session->is_ipv6=is_ipv6;

    if(is_ipv6) {
        memcpy(session->id,session_id,36);
        memcpy(session->src_addr,saddr,16);
        memcpy(session->dst_addr,daddr,16);

    }else{
        memcpy(session->id,session_id,12);
        memcpy(session->src_addr,saddr,4);
        memcpy(session->dst_addr,daddr,4);
    }

    session->peer_mss=1200;
    session->sport=tcphdr->src_port;
    session->dport=tcphdr->dst_port;
    session->seq=rand();
    session->my_window_size=TCP_DEFAULT_WIN_SIZE;

    session->peer_seq=tcphdr->seq_num+=1;
    session->peer_window_size=tcphdr->win_size;

    session->tcp_st=TCP_ST_SYN_SND;

    gettimeofday(&(session->data_time_up),NULL);

    my_mss=htons(session->my_mss);

    tcp_session_handle_header_opt(session,m->data+m->offset-hdr_len+20,hdr_len-20);
    rs=tcp_build_opts(opt_kinds,opt_values,opt_lenths,buf);

    tcp_send_data(session,TCP_SYN | TCP_ACK,buf,rs,NULL,0);
    session->sent_seq_cnt+=1;

    mbuf_put(m);
}

/// 发送缓冲区的数据
static void tcp_send_from_buf(struct tcp_session *session)
{
    // 根据窗口以及MTU计算出发送数据的大小
    int sent_size=0,tot_size=0;
    unsigned short peer_mss=session->peer_mss;
    unsigned short peer_wind=session->peer_window_size;
    unsigned short used_size=TCP_SENT_BUF(session)->used_size;

    unsigned char buf[0xffff];
    
    while(1){
        if(peer_wind==0) break;
        //if(peer_wind==0) return;

        sent_size=peer_mss>peer_wind?peer_wind:peer_mss;
        sent_size=tcp_buf_copy_from_tcp_buf(TCP_SENT_BUF(session),buf,sent_size);
        
        tcp_send_data(session,TCP_ACK,NULL,0,buf,sent_size);

        peer_wind-=sent_size;
        tot_size+=sent_size;

        //DBG("%d %d\r\n",tot_size,used_size);

        if(tot_size>=used_size) break;
        //if(tot_size>=used_size) return;
    }
}

/// 发送确认处理
static void tcp_sent_ack_handle(struct tcp_session *session,struct netutil_tcphdr *tcphdr)
{
    int used_size,ack_size;
    
    ack_size=tcphdr->ack_num-session->seq;
    // 此处考虑序列号回转情况
    if(ack_size<0) ack_size=abs(ack_size);
    used_size=tcp_buf_free_buf_get(TCP_SENT_BUF(session));

    // 如果确认大小大于缓冲区的大小那么忽略该数据包
    if(used_size<ack_size){
        DBG("wrong peer ack number\r\n");
        return;
    }

    //DBG("ack size %d\r\n",ack_size);
    tcp_buf_data_ptr_move(TCP_SENT_BUF(session),ack_size);

    session->seq+=ack_size;
    // 减少已经被确认的数据
    session->sent_seq_cnt-=ack_size;
}

/// 函数返回0表示该数据包无效或者非法,否则表示该数据包有效
static int tcp_session_ack(struct tcp_session *session,struct netutil_tcphdr *tcphdr,struct mbuf *m)
{
    int payload_len=m->tail-m->offset;
    unsigned int tmp=session->seq+session->sent_seq_cnt;

    session->delay_ms=tcp_session_get_data_delay(session);
    session->peer_window_size=tcphdr->win_size;
    
    // 如果确认号大于序列号那么丢弃数据包,这里考虑序列号回转情况
    // 对于序列号回转这部分采用丢包处理
    if(tcphdr->ack_num > tmp) return 0;

    if(TCP_ST_SYN_SND==session->tcp_st && session->peer_seq==tcphdr->seq_num){
        session->tcp_st=TCP_ST_OK;
        session->sent_seq_cnt-=1;
        session->seq+=1;
        netpkt_tcp_connect_ev(session->id,session->src_addr,session->dst_addr,session->sport,session->dport,session->is_ipv6);
        // 第三次握手如果没有数据那么直接返回;
        if(payload_len==0) return 1;
    }
    // 此处对发送的数据包进行确认并且发送发送缓冲区的数据
    if(tcphdr->seq_num==session->peer_seq){
        if(payload_len!=0 && session->tcp_st==TCP_ST_OK) {
            //DBG("recv length:%d\r\n",payload_len);
            session->peer_seq=tcphdr->seq_num+payload_len;
            netpkt_tcp_recv(session->id,tcphdr->win_size,session->is_ipv6,m->data+m->offset,payload_len);
        }
        tcp_sent_ack_handle(session,tcphdr);
        // 此处处理关闭ack的特殊情况
        if(session->tcp_st==TCP_ST_FIN_SND_WAIT){
            if(session->peer_sent_closed) {
                DBG("tcp four times closed\r\n");
                tcp_session_close(session);
            }
            return 1;
        }
        // 如果对端未关闭那么更新连接时间
        if(!session->peer_sent_closed) gettimeofday(&(session->conn_time_up),NULL);

        //DBG("%u\r\n",session->sent_seq_cnt);
        if(session->sent_seq_cnt!=0) tcp_send_from_buf(session);
        else tcp_send_data(session,TCP_ACK,NULL,0,NULL,0);

        return 1;
    }
    // 已经接收的数据发送ACK,此处要考虑序列号回转情况
    if(tcphdr->seq_num+payload_len<session->peer_seq) tcp_send_data(session,TCP_ACK,NULL,0,NULL,0);

    return 1;
}

static void tcp_session_fin(struct tcp_session *session,struct netutil_tcphdr *tcphdr,struct mbuf *m)
{
    session->peer_sent_closed=1;
}

static void tcp_session_rst(const char *session_id,unsigned char *saddr,unsigned char *daddr,struct netutil_tcphdr *tcphdr,int is_ipv6,struct mbuf *m)
{
    struct tcp_session *session=tcp_session_get((unsigned char *)session_id,is_ipv6);
    
    tcp_session_close(session);

    mbuf_put(m);
}

static void tcp_session_handle(unsigned char *saddr,unsigned char *daddr,struct netutil_tcphdr *tcphdr,int is_ipv6,struct mbuf *m)
{
    char key[36];
    char is_found;

    struct tcp_session *session=NULL;
    struct map *map=is_ipv6?tcp_sessions.sessions6:tcp_sessions.sessions;
    int ack,rst,syn,fin,hdr_len,r;

    unsigned short sport,dport,hdr_and_flags;
    unsigned int seq,ack_seq;

    if(is_ipv6){
        memcpy(key,saddr,16);
        memcpy(key+16,daddr,16);
        memcpy(key+32,&(tcphdr->src_port),2);
        memcpy(key+34,&(tcphdr->dst_port),2);
    }else{
        memcpy(key,saddr,4);
        memcpy(key,daddr,4);
        memcpy(key+8,&(tcphdr->src_port),2);
        memcpy(key+10,&(tcphdr->dst_port),2);
    }

    session=map_find(map,key,&is_found);

    sport=ntohs(tcphdr->src_port);
    dport=ntohs(tcphdr->dst_port);

    seq=ntohl(tcphdr->seq_num);
    ack_seq=ntohl(tcphdr->ack_num);

    hdr_and_flags=ntohs(tcphdr->header_len_and_flag);

    hdr_len=((hdr_and_flags & 0xf000) >> 12) * 4;
    ack= hdr_and_flags & TCP_ACK;
    rst=hdr_and_flags & TCP_RST;
    syn=hdr_and_flags & TCP_SYN;
    fin=hdr_and_flags & TCP_FIN;

    // 不存在session那么就丢弃数据包
    if((ack || rst || fin) && NULL==session){
        mbuf_put(m);
        return;
    }
    // TCP SYN不能携带任何数据
    if(m->tail-m->offset!=hdr_len && syn){
        DBG("wrong TCP SYN protocol format\r\n");
        mbuf_put(m);
        return;
    }
    // 如果值都没有设置那么丢弃数据包
    if(!ack && !rst && !syn && !fin){
        // 会话存在那么就删除会话数据包
        if(NULL!=session){
            STDERR("client send wrong tcp packet\r\n");
        }else{
            tcp_send_rst(session);
            // 发送错误并且关闭会话
            tcp_session_close(session);
        }
        DBG("wrong client TCP data format\r\n");
        mbuf_put(m);
        return;
    }

    tcphdr->src_port=sport;
    tcphdr->dst_port=dport;
    tcphdr->seq_num=seq;
    tcphdr->ack_num=ack_seq;
    tcphdr->win_size=ntohs(tcphdr->win_size);

    m->offset+=hdr_len;

    if(rst){
        tcp_session_rst(key,saddr,daddr,tcphdr,is_ipv6,m);
        return;
    }
    if(syn){
        tcp_session_syn(key,saddr,daddr,tcphdr,hdr_len,is_ipv6,m);
        return;
    }
    r=tcp_session_ack(session,tcphdr,m);
    if(fin && r) tcp_session_fin(session,tcphdr,m);
    // ack和fin的处理不自动回收mbuf
    mbuf_put(m);
}

static void tcp_handle_for_v4(struct mbuf *m)
{
    struct netutil_iphdr *header=(struct netutil_iphdr *)(m->data+m->offset);
    int hdr_len=(header->ver_and_ihl & 0x0f) * 4;
    struct netutil_tcphdr *tcphdr=(struct netutil_tcphdr *)(m->data+m->offset+hdr_len);

    m->offset=m->offset+hdr_len;
    tcp_session_handle(header->src_addr,header->dst_addr,tcphdr,0,m);
}

static void tcp_handle_for_v6(struct mbuf *m)
{
    struct netutil_ip6hdr *header=(struct netutil_ip6hdr *)(m->data+m->offset);
    struct netutil_tcphdr *tcphdr=(struct netutil_tcphdr *)(m->data+m->offset+40);

    m->offset=m->offset+40;
    tcp_session_handle(header->src_addr,header->dst_addr,tcphdr,1,m);
}

int tcp_init(void)
{
    struct map *m;
    int rs;

    bzero(&tcp_sessions,sizeof(struct tcp_sessions));

    tcp_sysloop=sysloop_add(tcp_sysloop_cb,NULL);

    if(NULL==tcp_sysloop){
        STDERR("cannot add to sysloop\r\n");
        return -1;
    }

    rs=map_new(&m,36);
    if(0!=rs){
        sysloop_del(tcp_sysloop);
        STDERR("cannot create map for TCPv6\r\n");
        return -1;
    }
    tcp_sessions.sessions6=m;

    rs=map_new(&m,12);
    if(0!=rs){
        sysloop_del(tcp_sysloop);
        map_release(tcp_sessions.sessions6,NULL);
        STDERR("cannot create map for TCP\r\n");
        return -1;
    }
    tcp_sessions.sessions=m;

    tcp_sessions.ip_mss=1420;
    tcp_sessions.ip6_mss=1200;

    return 0;
}

void tcp_uninit(void)
{
    map_release(tcp_sessions.sessions6,tcp_session_del_cb);
    map_release(tcp_sessions.sessions,tcp_session_del_cb);

    sysloop_del(tcp_sysloop);
}

int tcp_mss_set(unsigned short mss,int is_ipv6)
{
    if(mss<512){
        STDERR("min mss value is 512,but your value is %d\r\n",mss);
        return -1;
    }

    if(is_ipv6) tcp_sessions.ip6_mss=mss;
    else tcp_sessions.ip_mss=mss;

    return 0;
}

void tcp_handle(struct mbuf *m,int is_ipv6)
{
    if(is_ipv6) tcp_handle_for_v6(m);
    else tcp_handle_for_v4(m);
}

int tcp_send(unsigned char *session_id,void *data,int length,int is_ipv6)
{
    struct tcp_session *session=tcp_session_get(session_id,is_ipv6);
    int sent_size;

    if(NULL==session) return -1;
    // 如果本端关闭那么不允许发送数据
    if(session->my_sent_closed) return -2;
    
    // 如果未定义数据时间对象,那么定义数据时间对象
    if(NULL==session->data_tm_node){
        session->data_tm_node=tcp_timer_add(session->delay_ms,tcp_session_data_timeout_cb,session);
        if(NULL==session->data_tm_node){
            STDERR("cannot create data time node\r\n");
            return -3;
        }
    }

    sent_size=tcp_buf_free_buf_get(TCP_SENT_BUF(session));
    sent_size=sent_size>length?length:sent_size;

    session->sent_seq_cnt+=sent_size;

    tcp_buf_copy_to_tcp_buf(TCP_SENT_BUF(session),data,sent_size);

    // 发送数据,加入到定时器
    tcp_send_from_buf(session);

    // 如果已经超时了那么就更新,注意一定需要等待超时才能更新定时器
    if(session->data_tm_node->timeout_flags) tcp_timer_update(session->data_tm_node,session->delay_ms);

    return sent_size;
}

int tcp_close(unsigned char *session_id,int is_ipv6)
{
    struct tcp_session *session;

    session=tcp_session_get(session_id,is_ipv6);
    if(NULL==session) return -1;

    session->my_sent_closed=1;
    
    // 如果没有数据那么直接发送FIN数据帧,并且序列号加1
    if(TCP_SENT_BUF(session)->used_size){
        session->sent_seq_cnt+=1;
        tcp_send_data(session,TCP_ACK | TCP_FIN,NULL,0,NULL,0);
        tcp_session_fin_wait_set(session);
    }
    
    return 0;
}

int tcp_window_set(unsigned char *session_id,int is_ipv6,unsigned short win_size)
{
    struct tcp_session *session;
    session=tcp_session_get(session_id,is_ipv6);

    if(NULL==session) return -1;

    session->my_window_size=win_size;

    return 0;
}

inline
unsigned long long tcp_conn_count_get(void)
{
    return tcp_sessions.conn_count;
}