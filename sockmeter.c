/*
Sockmeter: a Windows network performance measurement tool.
Currently only supports TCP.

Compared to iperf: Optimized for Windows with IOCP.

Compared to ntttcp: Allows the thread count and socket count to be
separately configured; no need to re-run the service on each execution;
the service uses a single port number.

TODO:
-avg packet size
-cpu%
-latency
-write stats to json
-TCP_NODELAY option
-service sends back info (cpu% etc)
-consider SO_LINGER/SO_DONTLINGER
-pingpong
-UDP
-Should -nbytes be per-socket or across all sockets?
-Currently the service side thread count is min(64, numProc).
-Consider creating a number of threads equal to the number of
    RSS processors and assigning conns to threads based on the output of
    SIO_QUERY_RSS_PROCESSOR_INFO rather than round-robin.
-Less alarming messages for ungraceful connection closure on service
    side (or perhaps do graceful connection closure).
-cmdline args to force v4/6 when using hostnames
*/

#define WIN32_LEAN_AND_MEAN 1
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>
#include <winsock2.h>
#include <mswsock.h>
#include <ws2tcpip.h>
#include <mstcpip.h>
#include <iphlpapi.h>

#define VERSION "0.0.0"

#define USAGE \
"sockmeter version " VERSION "\n" \
"   Measures network performance.\n" \
"\n" \
"Usage:\n" \
"   sockmeter -v\n" \
"       Print the version.\n" \
"   sockmeter -svc [port]\n" \
"       Run sockmeter service, listening on port [port].\n" \
"   sockmeter [client_args]\n" \
"       Run sockmeter client.\n" \
"\n" \
"[client_args]:\n" \
"   -send [h] [p]:\n" \
"   -recv [h] [p]:\n" \
"   -sendrecv [h] [p]: Send/receive to/from host h at port p.\n" \
"                  Pass multiple times to send/receive data to/from\n" \
"                  multiple peers.\n" \
"   -nsock [#]: number of sockets.\n" \
"   -nthread [#]: number of threads.\n" \
"   -nbytes [#]: Total bytes (divided between sockets).\n" \
"   -t [#]: Total milliseconds (cannot pass both -nbytes and -t)\n" \
"   -sbuf [#]: Set SO_SNDBUF to [#] on each socket.\n" \
"   -rbuf [#]: Set SO_RCVBUF to [#] on each socket.\n" \
"   -iosize [#]: Set size of each socket send/recv call.\n" \
"\n" \
"Examples:\n" \
"   sockmeter -svc 30000\n" \
"   sockmeter -nsock 100 -nthread 4 -send 127.0.0.1 30000 -recv pc2 30001\n"

#define DEVBUILD
#ifdef DEVBUILD
    #define DEVTRACE printf
#else
    #define DEVTRACE(...)
#endif

typedef enum {
    SmDirectionSend,
    SmDirectionRecv,
    SmDirectionBoth
} SM_DIRECTION;

#pragma pack(push,1)
typedef struct {
    SM_DIRECTION dir;
    ULONG64 to_xfer;
} SM_REQ;
#pragma pack(pop)

typedef struct _SM_PEER {
    struct _SM_PEER* next;
    SOCKADDR_INET addr;
    int addrlen;
    SM_DIRECTION dir;
} SM_PEER;

typedef struct _SM_IO {
    WSAOVERLAPPED ov; // Assumed to be the first field.
    WSABUF wsabuf;
    DWORD recvflags;
    SM_DIRECTION dir;
    DWORD xferred;
    DWORD to_xfer; // Usually equal to bufsize.
    char* buf;
    int bufsize;
} SM_IO;

typedef struct _SM_CONN {
    struct _SM_CONN* next;
    SOCKET sock;
    SM_IO* io_tx;
    SM_IO* io_rx;
    ULONG64 xferred_tx;
    ULONG64 xferred_rx;
    ULONG64 to_xfer; // 0 means transfer indefinitely.
} SM_CONN;

typedef struct _SM_THREAD {
    struct _SM_THREAD* next;
    HANDLE t;
    HANDLE iocp;
    CRITICAL_SECTION lock;
    ULONG64 xferred_tx; // sum of bytes tx'd by deleted conns.
    ULONG64 xferred_rx; // sum of bytes rx'd by deleted conns.
    SM_CONN* conns;
    ULONG numconns;
} SM_THREAD;

// Variables for both client and service:
SM_THREAD* sm_threads;
int sm_iosize = 65535;

// Variables for client only:
SM_PEER* sm_peers;
ULONG64 sm_nbytes;
int sm_nsock;
int sm_nthread;
int sm_sbuf = -1;
int sm_rbuf = -1;
int sm_durationms = 0;
BOOLEAN sm_cleanup_time = FALSE;

// Variables for service only:
SOCKADDR_INET sm_svcaddr;
size_t sm_svcaddrlen;

ULONG64 sm_curtime_ms(void)
{
    static ULONG64 sm_perf_freq = 0; // ticks/sec
    if (sm_perf_freq == 0) {
        if (!QueryPerformanceFrequency((LARGE_INTEGER*)&sm_perf_freq)) {
            printf(
                "QueryPerformanceFrequency failed with %d\n", GetLastError());
            return 0;
        }
    }

    ULONG64 ticks = 0;
    if (!QueryPerformanceCounter((LARGE_INTEGER*)&ticks)) {
        printf("QueryPerformanceCounter failed with %d\n", GetLastError());
        return 0;
    }
    return ticks * 1000 / sm_perf_freq;
}

SM_PEER* sm_new_peer(wchar_t* host, wchar_t* port, SM_DIRECTION dir)
{
    int err = NO_ERROR;
    SM_PEER* peer = NULL;
    ADDRINFOW hints = {0};
    ADDRINFOW* res = NULL;

    peer = malloc(sizeof(SM_PEER));
    if (peer == NULL) {
        printf("Failed to allocate SM_PEER\n");
        err = ERROR_NOT_ENOUGH_MEMORY;
        goto exit;
    }
    memset(peer, 0, sizeof(*peer));

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (GetAddrInfoW(host, port, &hints, &res) != 0) {
        err = WSAGetLastError();
        printf("GetAddrInfoW failed: %d\n", err);
        goto exit;
    }

    if (res->ai_addr->sa_family == AF_INET) {
        SCOPE_ID scope = {0};
        SOCKADDR_IN* sa4 = (SOCKADDR_IN*)res->ai_addr;
        IN6ADDR_SETV4MAPPED(
            (SOCKADDR_IN6*)&peer->addr, &sa4->sin_addr, scope, sa4->sin_port);
    } else {
        memcpy((SOCKADDR*)&peer->addr, res->ai_addr, res->ai_addrlen);
    }
    peer->addrlen = sizeof(SOCKADDR_IN6);

    peer->dir = dir;

    peer->next = sm_peers;
    sm_peers = peer;

exit:
    if (err != NO_ERROR) {
        if (peer != NULL) {
            free(peer);
            peer = NULL;
        }
    }
    if (res != NULL) {
        FreeAddrInfoW(res);
    }
    return peer;
}

void sm_del_peer(SM_PEER* peer)
{
    SM_PEER** p = &sm_peers;
    while (*p != peer) {
        p = &((*p)->next);
    }
    *p = peer->next;

    free(peer);
}

SM_IO* sm_new_io(SM_DIRECTION dir)
{
    int err = NO_ERROR;
    SM_IO* io = NULL;

    io = malloc(sizeof(SM_IO));
    if (io == NULL) {
        printf("Failed to allocate SM_IO\n");
        err = ERROR_NOT_ENOUGH_MEMORY;
        goto exit;
    }
    memset(io, 0, sizeof(*io));

    io->ov.hEvent = WSACreateEvent();
    if (io->ov.hEvent == WSA_INVALID_EVENT) {
        err = WSAGetLastError();
        printf("WSACreateEvent failed with %d\n", err);
        goto exit;
    }

    io->dir = dir;
    io->xferred = 0;
    io->bufsize = sm_iosize;
    io->buf = malloc(io->bufsize);
    if (io->buf == NULL) {
        printf("failed to allocate IO buffer of size %d\n", io->bufsize);
        err = ERROR_NOT_ENOUGH_MEMORY;
        goto exit;
    }
    io->to_xfer = io->bufsize;
    io->wsabuf.buf = io->buf;
    io->wsabuf.len = io->to_xfer;

exit:
    if (err != NO_ERROR) {
        if (io != NULL) {
            if (io->ov.hEvent != WSA_INVALID_EVENT) {
                WSACloseEvent(io->ov.hEvent);
            }
            free(io);
            io = NULL;
        }
    }
    return io;
}

void sm_del_io(SM_IO* io)
{
    // TODO: Check HasOverlappedIoCompleted and cancel/wait for completion
    // if necessary.
    WSACloseEvent(io->ov.hEvent);
    free(io->buf);
    free(io);
}

SM_CONN* sm_new_conn(
    SM_THREAD* thread, SOCKET sock, SM_DIRECTION dir, ULONG64 to_xfer)
{
    int err = NO_ERROR;
    SM_CONN* conn = NULL;

    conn = malloc(sizeof(SM_CONN));
    if (conn == NULL) {
        printf("Failed to allocate SM_CONN\n");
        err = ERROR_NOT_ENOUGH_MEMORY;
        goto exit;
    }
    memset(conn, 0, sizeof(*conn));

    if (CreateIoCompletionPort(
            (HANDLE)sock, thread->iocp, (ULONG_PTR)conn, 0) == NULL) {
        err = GetLastError();
        printf("Associating sock to iocp failed with %d\n", err);
        goto exit;
    }

    if (dir == SmDirectionSend || dir == SmDirectionBoth) {
        conn->io_tx = sm_new_io(SmDirectionSend);
        if (conn->io_tx == NULL) {
            printf("Failed to create new send IO\n");
            err = ERROR_NOT_ENOUGH_MEMORY;
            goto exit;
        }
    }

    if (dir == SmDirectionRecv || dir == SmDirectionBoth) {
        conn->io_rx = sm_new_io(SmDirectionRecv);
        if (conn->io_rx == NULL) {
            printf("Failed to create new recv IO\n");
            err = ERROR_NOT_ENOUGH_MEMORY;
            goto exit;
        }
    }

    conn->sock = sock;
    conn->xferred_tx = 0;
    conn->xferred_rx = 0;
    conn->to_xfer = to_xfer;

    EnterCriticalSection(&thread->lock);
    conn->next = thread->conns;
    thread->conns = conn;
    thread->numconns++;
    LeaveCriticalSection(&thread->lock);

exit:
    if (err != NO_ERROR) {
        if (conn != NULL) {
            if (conn->io_tx != NULL) {
                sm_del_io(conn->io_tx);
            }
            if (conn->io_rx != NULL) {
                sm_del_io(conn->io_rx);
            }
            free(conn);
            conn = NULL;
        }
    }
    return conn;
}

void sm_del_conn(SM_THREAD* thread, SM_CONN* conn)
{
    EnterCriticalSection(&thread->lock);
    SM_CONN** c = &(thread->conns);
    while (*c != conn) {
        c = &((*c)->next);
    }
    *c = conn->next;
    thread->numconns--;
    thread->xferred_tx += conn->xferred_tx;
    thread->xferred_rx += conn->xferred_rx;
    LeaveCriticalSection(&thread->lock);

    if (conn->sock != INVALID_SOCKET) {
        closesocket(conn->sock);
    }
    if (conn->io_tx != NULL) {
        sm_del_io(conn->io_tx);
    }
    if (conn->io_rx != NULL) {
        sm_del_io(conn->io_rx);
    }

    free(conn);
}

SM_THREAD* sm_new_thread(LPTHREAD_START_ROUTINE fn)
{
    int err = NO_ERROR;
    SM_THREAD* thread = NULL;

    thread = malloc(sizeof(SM_THREAD));
    if (thread == NULL) {
        printf("Failed to allocate SM_THREAD\n");
        return NULL;
    }
    memset(thread, 0, sizeof(*thread));

    thread->iocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
    if (thread->iocp == NULL) {
        err = GetLastError();
        printf("CreateIoCompletionPort failed with %d\n", err);
        goto exit;
    }

    InitializeCriticalSection(&thread->lock);
    thread->numconns = 0;
    thread->conns = NULL;

    thread->t = CreateThread(NULL, 0, fn, (void*)thread, 0, NULL);
    if (thread->t == NULL) {
        err = GetLastError();
        printf("CreateThread failed with %d\n", err);
        goto exit;
    }

    thread->next = sm_threads;
    sm_threads = thread;

exit:
    if (err != NO_ERROR) {
        if (thread != NULL) {
            if (thread->t != NULL) {
                CloseHandle(thread->t);
            }
            if (thread->iocp != NULL) {
                CloseHandle(thread->iocp);
            }
            free(thread);
            thread = NULL;
        }
    }
    return thread;
}

void sm_del_thread(SM_THREAD* thread)
{
    // This is called from the main thread on termination, and we assume
    // the SM_THREAD's thread is already terminated.

    SM_THREAD** t = &sm_threads;
    while (*t != thread) {
        t = &((*t)->next);
    }
    *t = thread->next;

    // Normally conns are deleted as they finish, but in error conditions
    // we may terminate early and still have some conns to delete here.
    while (thread->conns != NULL) {
        sm_del_conn(thread, thread->conns);
    }

    CloseHandle(thread->t);
    CloseHandle(thread->iocp);
    free(thread);
}

int sm_start_conn(SM_CONN* conn)
{
    // Post initial IO(s), which will be subsequently reposted by sm_io_loop.

    int err = NO_ERROR;

    if (conn->io_tx != NULL) {
        if (WSASend(
                conn->sock, &(conn->io_tx->wsabuf), 1, NULL,
                0, &(conn->io_tx->ov), NULL) == SOCKET_ERROR) {
            err = WSAGetLastError();
            if (err != WSA_IO_PENDING) {
                printf("WSASend failed with %d\n", err);
                goto exit;
            } else {
                err = NO_ERROR;
            }
        }
    }

    if (conn->io_rx != NULL) {
        if (WSARecv(
                conn->sock, &(conn->io_rx->wsabuf), 1, NULL,
                &(conn->io_rx->recvflags), &(conn->io_rx->ov), NULL)
                    == SOCKET_ERROR) {
            err = WSAGetLastError();
            if (err != WSA_IO_PENDING) {
                printf("WSARecv failed with %d\n", err);
                goto exit;
            } else {
                err = NO_ERROR;
            }
        }
    }

exit:
    return err;
}

int sm_io_loop(SM_THREAD* thread, ULONG timeout_ms)
{
    // Loop on GetQueuedCompletionStatus, reposting IOs or shutting down
    // conns as appropriate.

    int err = NO_ERROR;
    int xferred = 0;
    SM_CONN* conn = NULL;
    SM_IO* io = NULL;

    while (TRUE) {

        if (!GetQueuedCompletionStatus(
                thread->iocp, (DWORD*)&xferred, (ULONG_PTR*)&conn,
                (LPOVERLAPPED*)&io, timeout_ms)) {
            err = GetLastError();
            printf("GetQueuedCompletionStatus failed with %d\n", err);
            goto exit;
        }

        if (sm_cleanup_time || xferred == 0) {
            break;
        }

        // Figure out how much to transfer next and adjust the wsabuf
        // appropriately: Either we want to transfer the remainder of the IO, or
        // we want to resend the IO from the beginning, or we are near the end
        // of the stream and want to send only part of the IO.

        // Reminder: (conn->to_xfer == 0) means send forever.

        ULONG64* conn_dir_xferred;
        if (io->dir == SmDirectionSend) {
            conn_dir_xferred = &conn->xferred_tx;
        } else {
            conn_dir_xferred = &conn->xferred_rx;
        }

        io->xferred += xferred;
        if (io->xferred < io->to_xfer) {
            io->wsabuf.buf = &(io->buf[io->xferred]);
            io->wsabuf.len = io->to_xfer - io->xferred;
        } else if (conn->to_xfer == 0 ||
                   conn->to_xfer > *conn_dir_xferred + io->to_xfer) {
            *conn_dir_xferred += io->to_xfer;
            if (conn->to_xfer != 0 &&
                io->to_xfer > (conn->to_xfer - *conn_dir_xferred)) {
                io->to_xfer = (DWORD)(conn->to_xfer - *conn_dir_xferred);
            }
            io->wsabuf.buf = io->buf;
            io->wsabuf.len = io->to_xfer;
            io->xferred = 0;
        } else {
            *conn_dir_xferred = conn->to_xfer;
        }

        if (conn->to_xfer == 0 || *conn_dir_xferred < conn->to_xfer) {
            if (io->dir == SmDirectionSend) {
                if (WSASend(
                        conn->sock, &(io->wsabuf), 1, NULL, 0, &(io->ov), NULL)
                            == SOCKET_ERROR) {
                    err = WSAGetLastError();
                    if (err != WSA_IO_PENDING) {
                        printf("WSASend failed with %d\n", err);
                        goto exit;
                    } else {
                        err = NO_ERROR;
                    }
                }
            } else {
                if (WSARecv(
                        conn->sock, &(io->wsabuf), 1, NULL,
                        &(io->recvflags), &(io->ov), NULL)
                            == SOCKET_ERROR) {
                    err = WSAGetLastError();
                    if (err != WSA_IO_PENDING) {
                        printf("WSARecv failed with %d\n", err);
                        goto exit;
                    } else {
                        err = NO_ERROR;
                    }
                }
            }
        } else {
            shutdown(conn->sock, SD_BOTH);
            sm_del_conn(thread, conn);
            if (thread->numconns == 0) {
                break;
            }
        }
    }

exit:
    return err;
}

int sm_connect_conn(SM_THREAD* thread, SM_PEER* peer)
{
    // Create an outbound connection and an SM_CONN for it.

    int err = NO_ERROR;
    SOCKET sock = INVALID_SOCKET;

    sock = WSASocket(
        AF_INET6, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
    if (sock == INVALID_SOCKET) {
        err = WSAGetLastError();
        printf("socket failed with %d\n", err);
        goto exit;
    }

    int opt = 0;
    if (setsockopt(
            sock, IPPROTO_IPV6, IPV6_V6ONLY, (char*)&opt, sizeof(opt))
                == SOCKET_ERROR) {
        err = WSAGetLastError();
        printf("setsockopt(IPV6_V6ONLY) failed with %d\n", err);
        goto exit;
    }

    if (sm_sbuf != -1) {
        if (setsockopt(
                sock, SOL_SOCKET, SO_SNDBUF, (char*)&sm_sbuf,
                sizeof(sm_sbuf)) == SOCKET_ERROR) {
            err = WSAGetLastError();
            printf("setsockopt(SO_SNDBUF) failed with %d\n", err);
            goto exit;
        }
    }

    if (sm_rbuf != -1) {
        if (setsockopt(
                sock, SOL_SOCKET, SO_RCVBUF, (char*)&sm_sbuf,
                sizeof(sm_sbuf)) == SOCKET_ERROR) {
            err = WSAGetLastError();
            printf("setsockopt(SO_RCVBUF) failed with %d\n", err);
            goto exit;
        }
    }

    SM_CONN* conn = sm_new_conn(thread, sock, peer->dir, sm_nbytes / sm_nsock);
    if (conn == NULL) {
        err = ERROR_NOT_ENOUGH_MEMORY;
        printf("Failed to create new conn\n");
        goto exit;
    }

    if (connect(conn->sock, (SOCKADDR*)&peer->addr, peer->addrlen)
            == SOCKET_ERROR) {
        err = WSAGetLastError();
        printf("connect failed with %d\n", err);
        goto exit;
    }

    SM_REQ req = {0};
    // If we send then the service receives, and vice versa.
    switch (peer->dir) {
    case SmDirectionSend:
        req.dir = SmDirectionRecv;
        break;
    case SmDirectionRecv:
        req.dir = SmDirectionSend;
        break;
    case SmDirectionBoth:
        req.dir = SmDirectionBoth;
        break;
    }
    req.to_xfer = conn->to_xfer;
    int bytes_sent = send(conn->sock, (char*)&req, sizeof(req), 0);
    if (bytes_sent == SOCKET_ERROR) {
        err = WSAGetLastError();
        printf("send (req) failed with %d\n", err);
        goto exit;
    } else if (bytes_sent != sizeof(req)) {
        err = 1;
        printf("send unexpectedly sent only part of req\n");
        goto exit;
    }

exit:
    if (err != NO_ERROR) {
        if (sock != INVALID_SOCKET) {
            closesocket(sock);
        }
    }
    return err;
}

SM_CONN* sm_accept_conn(SOCKET ls, SM_THREAD* thread)
{
    // Call accept on the input listening socket, and create an SM_CONN for
    // the resulting inbound connection.

    int err = NO_ERROR;
    SM_CONN* conn = NULL;

    SOCKET ss = accept(ls, NULL, NULL);
    if (ss == INVALID_SOCKET) {
        err = WSAGetLastError();
        printf("Accept failed with %d\n", err);
        goto exit;
    }

    DEVTRACE("Accepted connection\n");

    SM_REQ req = {0};
    int xferred = recv(ss, (char*)&req, sizeof(req), MSG_WAITALL);
    if (xferred == SOCKET_ERROR) {
        err = WSAGetLastError();
        printf("recv(req) failed with %d\n", err);
        goto exit;
    }

    conn = sm_new_conn(thread, ss, req.dir, req.to_xfer);
    if (conn == NULL) {
        err = ERROR_NOT_ENOUGH_MEMORY;
        printf("Failed to create new conn for accept socket\n");
        goto exit;
    }
    ss = INVALID_SOCKET; // conn owns socket now.

exit:
    if (err != NO_ERROR) {
        if (conn != NULL) {
            sm_del_conn(thread, conn);
            conn = NULL;
        }
        if (ss != INVALID_SOCKET) {
            closesocket(ss);
        }
    }
    return conn;
}

DWORD sm_service_fn(void* param)
{
    while (TRUE) {
        sm_io_loop((SM_THREAD*)param, INFINITE);
    }
    return 0;
}

void sm_service(void)
{
    int err = 0;
    SOCKET ls = INVALID_SOCKET;
    SM_THREAD* thread = NULL;

    SYSTEM_INFO sysinfo;
    GetSystemInfo(&sysinfo);
    DWORD num_threads = min(sysinfo.dwNumberOfProcessors, 64);
    printf(
        "NumberOfProcessors = %lu; Creating %lu threads\n",
        sysinfo.dwNumberOfProcessors, num_threads);
    for (DWORD i = 0; i < num_threads; i++) {
        sm_new_thread(sm_service_fn);
    }

    ls = WSASocket(
        AF_INET6, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
    if (ls == INVALID_SOCKET) {
        printf("socket failed with %d\n", WSAGetLastError());
        goto exit;
    }

    int opt = 0;
    if (setsockopt(
            ls, IPPROTO_IPV6, IPV6_V6ONLY, (char*)&opt, sizeof(opt)) != 0) {
        printf("setsockopt(IPV6_V6ONLY) failed with %d\n", WSAGetLastError());
        goto exit;
    }

    if (bind(ls, (SOCKADDR*)&sm_svcaddr, (int)sm_svcaddrlen) == SOCKET_ERROR) {
        printf("bind failed with %d\n", WSAGetLastError());
        goto exit;
    }

    if (listen(ls, SOMAXCONN) == SOCKET_ERROR) {
        printf("listen failed with %d\n", WSAGetLastError());
        goto exit;
    }

    DEVTRACE("Listening on port %u\n", ntohs(SS_PORT(&sm_svcaddr)));

    thread = sm_threads;
    while (TRUE) {
        SM_CONN* conn = sm_accept_conn(ls, thread);
        if (conn == NULL) {
            goto exit;
        }
        thread = thread->next;
        if (thread == NULL) {
            thread = sm_threads;
        }

        err = sm_start_conn(conn);
        if (err != 0) {
            goto exit;
        }
    }

exit:
    if (ls != INVALID_SOCKET) {
        closesocket(ls);
    }
}

DWORD sm_client_fn(void* param)
{
    return sm_io_loop((SM_THREAD*)param, 5000);
}

void sm_client(void)
{
    int err = NO_ERROR;
    SM_THREAD* thread = NULL;
    SM_PEER* peer = NULL;
    SM_CONN* conn = NULL;

    for (int i = 0; i < sm_nthread; i++) {
        thread = sm_new_thread(sm_client_fn);
        if (thread == NULL) {
            return;
        }
    }

    printf("Connecting...\n");

    // Assign conns to threads and peers round-robin.
    //
    // We first connect all conns and then start all conns, rather than
    // starting each conn as it's connected. This is for two reasons:
    // 1) If we fail to connect to one of multiple peers, we will abort and
    //    it's better not to have started transferring data with the other
    //    peers.
    // 2) This makes synchronization in sm_io_loop easier- we add all the conns
    //    to the thread so that "numconns" is a complete count, and only then
    //    do we post the IOs, so we won't have a race where numconns drops
    //    back to zero before we've added all of the conns.

    thread = sm_threads;
    peer = sm_peers;
    for (int i = 0; i < sm_nsock; i++) {
        err = sm_connect_conn(thread, peer);
        if (err != 0) {
            return;
        }
        thread = thread->next;
        if (thread == NULL) {
            thread = sm_threads;
        }
        peer = peer->next;
        if (peer == NULL) {
            peer = sm_peers;
        }
    }

    printf("Testing...\n");

    // TODO: consider including connection establishment in the timing.

    ULONG64 t_start_ms = sm_curtime_ms();

    thread = sm_threads;
    while (thread != NULL) {
        // Hold thread lock while we walk the conn list in case a conn finishes
        // and wants to be removed from the list before we're done walking.
        EnterCriticalSection(&thread->lock);
        conn = thread->conns;
        while (conn != NULL) {
            err = sm_start_conn(conn);
            if (err != 0) {
                LeaveCriticalSection(&thread->lock);
                return;
            }
            conn = conn->next;
        }
        LeaveCriticalSection(&thread->lock);
        thread = thread->next;
    }

    if (sm_durationms > 0) {
        err = SleepEx(sm_durationms, FALSE);
        sm_cleanup_time = TRUE;
    }

    thread = sm_threads;
    while (thread != NULL) {
        WaitForSingleObject(thread->t, INFINITE);
        thread = thread->next;
    }

    ULONG64 t_end_ms = sm_curtime_ms();
    ULONG64 t_elapsed_ms = t_end_ms - t_start_ms;

    printf("Finished.\n");

    if (t_elapsed_ms == 0) {
        printf("WARNING: transfer took less than 1ms; need to run longer.\n");
    } else {
        ULONG64 xferred_tx = 0;
        ULONG64 xferred_rx = 0;
        thread = sm_threads;
        while (thread != NULL) {
            // Depending on whether we're in -t or -nbytes mode, the conns
            // may or may not have been deleted at this point. So add the
            // thread's count of bytes xferred by deleted conns to the
            // counts in any active conns.
            EnterCriticalSection(&thread->lock);
            xferred_tx += thread->xferred_tx;
            xferred_rx += thread->xferred_rx;
            conn = thread->conns;
            while (conn != NULL) {
                xferred_tx += conn->xferred_tx;
                xferred_rx += conn->xferred_rx;
                conn = conn->next;
            }
            LeaveCriticalSection(&thread->lock);
            thread = thread->next;
        }
        printf(
            "\nthreads: %d\n"
            "sockets: %d\n"
            "dt_ms: %llu\n"
            "tx_bytes: %llu\n"
            "tx_Mbps: %llu\n"
            "rx_bytes: %llu\n"
            "rx_Mbps: %llu\n",
            sm_nthread,
            sm_nsock,
            t_elapsed_ms,
            (ULONG64)xferred_tx,
            (xferred_tx * 8) / (t_elapsed_ms * 1000),
            (ULONG64)xferred_rx,
            (xferred_rx * 8) / (t_elapsed_ms * 1000));
    }
}

int __cdecl wmain(int argc, wchar_t** argv)
{
    int err = 0;
    BOOLEAN need_wsacleanup = FALSE;
    WSADATA wd = {0};
    BOOLEAN svcmode = FALSE;
    int numpeers = 0;

    if (argc == 1) {
        printf(USAGE);
        goto exit;
    } else if (argc == 2 && !wcscmp(argv[1], L"-v")) {
        printf("%s\n", VERSION);
        goto exit;
    }

    err = WSAStartup(MAKEWORD(2,0), (LPWSADATA)&wd);
    if (err != 0) {
        printf("WSAStartup failed with %d\n", err);
        goto exit;
    }
    need_wsacleanup = TRUE;

    int ac = 1;
    wchar_t** av = argv + 1;

    while (ac < argc) {
        wchar_t** name = av++; ac++;
        int argsleft = argc - ac;
        if (argsleft >= 1 && !wcscmp(*name, L"-svc")) {
            IN6ADDR_SETANY((SOCKADDR_IN6*)&sm_svcaddr);
            SS_PORT(&sm_svcaddr) = htons((USHORT)_wtoi(*av));
            sm_svcaddrlen = SOCKADDR_SIZE(AF_INET6);
            svcmode = TRUE;
            av++; ac++;
        } else if (argsleft >= 1 && !wcscmp(*name, L"-nsock")) {
            sm_nsock = _wtoi(*av);
            av++; ac++;
        } else if (argsleft >= 1 && !wcscmp(*name, L"-nthread")) {
            sm_nthread = _wtoi(*av);
            av++; ac++;
        } else if (argsleft >= 1 && !wcscmp(*name, L"-nbytes")) {
            sm_nbytes = _wtoi64(*av);
            av++; ac++;
        } else if (argsleft >= 1 && !wcscmp(*name, L"-t")) {
            sm_durationms = _wtoi(*av);
            av++; ac++;
        } else if (argsleft >= 1 && !wcscmp(*name, L"-sbuf")) {
            sm_sbuf = _wtoi(*av);
            av++; ac++;
        } else if (argsleft >= 1 && !wcscmp(*name, L"-rbuf")) {
            sm_rbuf = _wtoi(*av);
            av++; ac++;
        } else if (argsleft >= 1 && !wcscmp(*name, L"-iosize")) {
            sm_iosize = _wtoi(*av);
            av++; ac++;
        } else if (argsleft >= 2 && !wcscmp(*name, L"-send")) {
            if (sm_new_peer(*av, *(av + 1), SmDirectionSend) == NULL) {
                printf("Failed to parse \"-send %ls %ls\"\n", *av, *(av + 1));
                err = ERROR_INVALID_PARAMETER;
                goto exit;
            }
            numpeers++;
            av += 2; ac += 2;
        } else if (argsleft >= 2 && !wcscmp(*name, L"-recv")) {
            if (sm_new_peer(*av, *(av + 1), SmDirectionRecv) == NULL) {
                printf("Failed to parse \"-recv %ls %ls\"\n", *av, *(av + 1));
                err = ERROR_INVALID_PARAMETER;
                goto exit;
            }
            numpeers++;
            av += 2; ac += 2;
        } else if (argsleft >= 2 && !wcscmp(*name, L"-sendrecv")) {
            if (sm_new_peer(*av, *(av + 1), SmDirectionBoth) == NULL) {
                printf("Failed to parse \"-sendrecv %ls %ls\"\n", *av, *(av + 1));
                err = ERROR_INVALID_PARAMETER;
                goto exit;
            }
            numpeers++;
            av += 2; ac += 2;
        } else {
            printf(USAGE);
            err = ERROR_INVALID_PARAMETER;
            goto exit;
        }
    }

    if (svcmode && numpeers > 0) {
        printf("ERROR: cannot pass both -svc and (-send or -recv or -sendrecv).\n");
        err = ERROR_INVALID_PARAMETER;
        goto exit;
    }

    if (sm_iosize == 0) {
        printf("ERROR: cannot set -iosize to 0.\n");
        err = ERROR_INVALID_PARAMETER;
        goto exit;
    }

    if (sm_nbytes != 0 && sm_iosize > sm_nbytes) {
        // This restriction is mainly for convenience- we always post a
        // full IO up front.
        printf("ERROR: cannot set -iosize larger than -nbytes.\n");
        err = ERROR_INVALID_PARAMETER;
        goto exit;
    }

    if (sm_nbytes != 0 && sm_durationms != 0) {
        printf("ERROR: cannot pass both -t and -nbytes.\n");
        err = ERROR_INVALID_PARAMETER;
        goto exit;
    }

    if (svcmode) {
        sm_service();
    } else {
        if (sm_durationms == 0 && sm_nbytes == 0) {
            printf("ERROR: Must pass -t or -nbytes.\n");
            err = ERROR_INVALID_PARAMETER;
            goto exit;
        }
        if (sm_nthread == 0) {
            printf("ERROR: Must pass -nthread.\n");
            err = ERROR_INVALID_PARAMETER;
            goto exit;
        }
        if (sm_nsock == 0) {
            printf("ERROR: Must pass -nsock.\n");
            err = ERROR_INVALID_PARAMETER;
            goto exit;
        }
        if (numpeers == 0) {
            printf("ERROR: Must pass -send or -recv at least once\n");
            err = ERROR_INVALID_PARAMETER;
            goto exit;
        }
        if (sm_nthread > sm_nsock) {
            printf("ERROR: Cannot have more threads than sockets.\n");
            err = ERROR_INVALID_PARAMETER;
            goto exit;
        }
        if (numpeers > sm_nsock) {
            printf("ERROR: Cannot have more peers than sockets.\n");
            err = ERROR_INVALID_PARAMETER;
            goto exit;
        }
        sm_client();
    }

exit:
    while (sm_threads != NULL) {
        sm_del_thread(sm_threads);
    }

    while (sm_peers != NULL) {
        sm_del_peer(sm_peers);
    }

    if (need_wsacleanup) {
        WSACleanup();
    }

    return err;
}
