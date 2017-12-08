cmake_minimum_required(VERSION 3.8)
project(tcp_stack)

set(CMAKE_CXX_STANDARD 11)

set(SOURCE_FILES
        example/list_example.c
        example/pthread_example.c
        include/arp.h
        include/arpcache.h
        include/base.h
        include/checksum.h
        include/ether.h
        include/hash.h
        include/icmp.h
        include/ip.h
        include/list.h
        include/log.h
        include/packet.h
        include/ring_buffer.h
        include/rtable.h
        include/synch_wait.h
        include/tcp.h
        include/tcp_apps.h
        include/tcp_hash.h
        include/tcp_sock.h
        include/tcp_timer.h
        include/types.h
        main.c
        tcp.c
        tcp_apps.c
        tcp_in.c
        tcp_out.c
        tcp_sock.c
        tcp_timer.c)

add_executable(tcp_stack ${SOURCE_FILES})