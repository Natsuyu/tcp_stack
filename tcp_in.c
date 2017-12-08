#include "tcp.h"
#include "tcp_sock.h"
#include "tcp_timer.h"

#include "log.h"
#include "ring_buffer.h"
#include "include/tcp.h"
#include "include/tcp_sock.h"

#include <stdlib.h>

// handling incoming packet for TCP_LISTEN state
//
// 1. malloc a child tcp sock to serve this connection request; 
// 2. send TCP_SYN | TCP_ACK by child tcp sock;
// 3. hash the child tcp sock into established_table (because the 4-tuple 
//    is determined).
void tcp_state_listen(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet)
{
	fprintf(stdout, "TODO: tcp_state_listen.\n");

	if(tsk->accept_backlog >= tsk->backlog) return;
	//监听端口，如果不是SYN报文：如果不是RST，回复RST包，否则，忽略
	if(cb->flags != TCP_SYN) {
		if(!(cb->flags & TCP_RST)) {
			tcp_send_reset(cb);
		}
		return;
	}

	struct tcp_sock *child = alloc_tcp_sock();
	child->parent = tsk;

	//初始化套接字的目的、源地址，端口号，和cb相反
	child->sk_sip = cb->daddr;
	child->sk_sport = cb->dport;
	child->sk_dip = cb->saddr;
	child->sk_dport = cb->sport;

	//更新ACK值
	child->rcv_nxt = cb->seq + 1;

	//改变状态
	tcp_set_state(child, TCP_SYN_RECV);

	//把套接字放入established table，并加入父套接字的listen队列中
	tcp_hash(child);
	//？？？这里是child->list 还是child->listen_queue
	list_add_tail(&child->list,&tsk->listen_queue);

	tcp_send_control_packet(child, TCP_SYN | TCP_ACK);

}

// handling incoming packet for TCP_CLOSED state, by replying TCP_RST
void tcp_state_closed(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet)
{
	tcp_send_reset(cb);
}

// handling incoming packet for TCP_SYN_SENT state
//
// If everything goes well (the incoming packet is TCP_SYN|TCP_ACK), reply with 
// TCP_ACK, and enter TCP_ESTABLISHED state, notify tcp_sock_connect; otherwise, 
// reply with TCP_RST.
void tcp_state_syn_sent(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet)
{
	fprintf(stdout, "TODO: tcp_state_syn_sent.\n");

	if((cb->flags & (TCP_SYN|TCP_ACK)) == (TCP_SYN|TCP_ACK)) {
		//ACK+1
		tsk->rcv_nxt = cb->seq + 1;

		tcp_set_state(tsk, TCP_ESTABLISHED);

		tcp_send_control_packet(tsk, TCP_ACK);

		//等待连接
		wake_up(tsk->wait_connect);
	}
	else
	{
		//如果遇到非SYN包，回复RST或者忽略
		if(!(cb->flags & TCP_RST))
			tcp_send_reset(cb);
	}

}

// update the snd_wnd of tcp_sock
//
// if the snd_wnd before updating is zero, notify tcp_sock_send (wait_send)
static inline void tcp_update_window(struct tcp_sock *tsk, struct tcp_cb *cb)
{
	u16 old_snd_wnd = tsk->snd_wnd;
	tsk->snd_wnd = cb->rwnd;
	if (old_snd_wnd == 0)
		wake_up(tsk->wait_send);
}

// update the snd_wnd safely: cb->ack should be between snd_una and snd_nxt
static inline void tcp_update_window_safe(struct tcp_sock *tsk, struct tcp_cb *cb)
{
	if (tsk->snd_una <= cb->ack && cb->ack <= tsk->snd_nxt)
		tcp_update_window(tsk, cb);
}

// handling incoming ack packet for tcp sock in TCP_SYN_RECV state
//
// 1. remove itself from parent's listen queue;
// 2. add itself to parent's accept queue;
// 3. wake up parent (wait_accept) since there is established connection in the
//    queue.
void tcp_state_syn_recv(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet)
{
	fprintf(stdout, "TODO: tcp_state_syn_recv.\n");

	if(!tsk->parent) return;
	if(!(cb->flags & TCP_ACK)) {
		if(!(cb->flags & TCP_RST)) {
			tcp_send_reset(cb);
		}

		return;
	}

	//从父套接字中删除自己？？？
	list_delete_entry(&tsk->list);

	//??? if(tcp_sock_accept_queue_full(tsk)) return;
	tcp_sock_accept_enqueue(tsk);

	//改变状态
	tcp_set_state(tsk, TCP_ESTABLISHED);

	wake_up(tsk->parent->wait_accept);
}

#ifndef max
#	define max(x,y) ((x)>(y) ? (x) : (y))
#endif

// check whether the sequence number of the incoming packet is in the receiving
// window
static inline int is_tcp_seq_valid(struct tcp_sock *tsk, struct tcp_cb *cb)
{
	u32 rcv_end = tsk->rcv_nxt + max(tsk->rcv_wnd, 1);
	if (cb->seq < rcv_end && tsk->rcv_nxt <= cb->seq_end) {
		return 1;
	}
	else {
		log(ERROR, "received packet with invalid seq, drop it.");
		return 0;
	}
}

// put the payload of the incoming packet into rcv_buf, and notify the
// tcp_sock_read (wait_recv)
int tcp_recv_data(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet)
{
	fprintf(stdout, "TODO: tcp_recv_data.\n");

	if(cb->pl_len > 0) {
		tsk->rcv_nxt += cb->pl_len;
		write_ring_buffer(tsk->rcv_buf, cb->payload, cb->pl_len);
	}

	return wake_up(tsk->wait_recv);
}

// Process an incoming packet as follows:
// 	 1. if the state is TCP_CLOSED, hand the packet over to tcp_state_closed;
// 	 2. if the state is TCP_LISTEN, hand it over to tcp_state_listen;
// 	 3. if the state is TCP_SYN_SENT, hand it to tcp_state_syn_sent;
// 	 4. check whether the sequence number of the packet is valid, if not, drop
// 	    it;
// 	 5. if the TCP_RST bit of the packet is set, close this connection, and
// 	    release the resources of this tcp sock;
// 	 6. if the TCP_SYN bit is set, reply with TCP_RST and close this connection,
// 	    as valid TCP_SYN has been processed in step 2 & 3;
// 	 7. check if the TCP_ACK bit is set, since every packet (except the first 
//      SYN) should set this bit;
//   8. process the ack of the packet: if it ACKs the outgoing SYN packet, 
//      establish the connection; if it ACKs new data, update the window;
//      if it ACKs the outgoing FIN packet, switch to correpsonding state;
//   9. process the payload of the packet: call tcp_recv_data to receive data;
//  10. if the TCP_FIN bit is set, update the TCP_STATE accordingly;
//  11. at last, do not forget to reply with TCP_ACK if the connection is alive.
void tcp_process(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet)
{
	fprintf(stdout, "TODO: tcp_process.\n");
	
	switch(tsk->state){
		case TCP_CLOSED:
			tcp_state_closed(tsk, cb, packet);
			return;
		case TCP_LISTEN:
			tcp_state_listen(tsk, cb, packet);
			return;
		case TCP_SYN_SENT:
			tcp_state_syn_sent(tsk, cb, packet);
			return;
		case TCP_SYN_RECV:
			tcp_state_syn_recv(tsk, cb, packet);
			return;
	}

	if(!is_tcp_seq_valid(tsk, cb)) return;

	//change to tco_closed
	if(tsk->state == TCP_LAST_ACK && (cb->flags & TCP_ACK)) {
		tcp_set_state(tsk, TCP_CLOSED);
		goto close;
	}

	if(cb->flags & TCP_RST) {
		goto close;
	}

	if(cb->flags & TCP_SYN) {
		tcp_send_reset(cb);
		return;
	}

	//if the state == tcp_established
	if(tsk->state == TCP_ESTABLISHED && (cb->flags == TCP_ACK || ((cb->flags & (TCP_ACK|TCP_PSH)) == (TCP_ACK|TCP_PSH)))) {
		tcp_update_window_safe(tsk, cb);
		tcp_recv_data(tsk, cb, packet);
		return;
	}

	//change to tcp_close_wait
	if(tsk->state == TCP_ESTABLISHED && (cb->flags & TCP_FIN)) {
		tcp_set_state(tsk, TCP_CLOSE_WAIT);
		tcp_send_control_packet(tsk, TCP_ACK);
		return;
	}

	//change to tcp_fin_wait_2
	if(tsk->state == TCP_FIN_WAIT_2 && (cb->flags & TCP_ACK)) {
		tcp_set_state(tsk, TCP_FIN_WAIT_2);
		return;
	}

	//change to timewait
	if(tsk->state == TCP_FIN_WAIT_2 && (cb->flags & TCP_FIN)) {
		tcp_set_state(tsk, TCP_TIME_WAIT);
		tcp_send_control_packet(tsk, TCP_ACK);
		tcp_set_timewait_timer(tsk);

		return;
	}



	close:

		free_tcp_sock(tsk);


}
