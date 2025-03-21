/*
Sockmeter: a Windows TCP performance measurement tool.

Compared to iperf: Optimized for Windows with IOCP.

Compared to ntttcp: Allows the thread count and socket count to be
separately configured; no need to re-run the service on each execution;
the service uses a single port number.

TODO:
-add metric: avg packet size
-add metric: cpu%
-add metric: req latency
-write stats to json
-iofrag option (pass multiple wsabufs to WSASend/WSARecv)
-reuseconn option (default true; whether to reuse conns for new reqs)
-TCP_NODELAY option
-service sends back info (cpu% etc)
-consider SO_LINGER/SO_DONTLINGER
-pingpong
-Currently the service side thread count is min(64, numProc).
    Consider creating a number of threads equal to the number of
    RSS processors and assigning conns to threads based on the output of
    SIO_QUERY_RSS_PROCESSOR_INFO rather than round-robin.
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

#define VERSION "1.0.1"

#define USAGE \
"\nsockmeter version " VERSION "\n" \
"\n" \
"Measures network performance.\n" \
"Sockmeter client connects to one or more peers running sockmeter\n" \
"service. On each connection, the client issues a series of\n" \
"requests to send and/or receive data.\n" \
"\n" \
"Usage:\n" \
"   sockmeter -v\n" \
"       Print the version.\n" \
"   sockmeter -svc [p]\n" \
"       Run service, listening on port p. See also \"Daemon mode\" below.\n" \
"   sockmeter [client_args]\n" \
"       Run client.\n" \
"\n" \
"[client_args]:\n" \
"   -tx [h] [p]:\n" \
"   -rx [h] [p]:\n" \
"   -txrx [h] [p]:\n" \
"         Connect to host h at port p.\n" \
"         Pass multiple times to connect to multiple hosts.\n" \
"   -t [#]: How long to run in milliseconds. If not passed, a single request\n" \
"           is issued on each connection.\n" \
"   -reqsize [#]: bytes transferred per request (default: 16MB).\n" \
"   -nsock [#]: number of sockets (default: 1).\n" \
"   -nthread [#]: number of threads (default: 1).\n" \
"   -iosize [#]: Bytes passed in each send/recv (default: 64KB).\n" \
"   -sbuf [#]: Set SO_SNDBUF to [#] on each socket (default: not set).\n" \
"   -rbuf [#]: Set SO_RCVBUF to [#] on each socket (default: not set).\n" \
"\n" \
"Examples:\n" \
"   sockmeter -svc 30000\n" \
"   sockmeter -nsock 100 -nthread 4 -tx 127.0.0.1 30000 -rx pc2 30001\n" \
"\n" \
"Daemon mode:\n" \
"As an alternative to running the service in an active terminal session,\n" \
"sockmeter can be started as an actual service:\n" \
"   sc create sockmeter binPath= \"C:\\sockmeter.exe -d\" start= auto\n" \
"   sc start sockmeter -svc [p]\n" \
"The service can then be stopped and deleted with:\n" \
"   sc stop sockmeter\n" \
"   sc delete sockmeter\n"

#ifdef _DEBUG
    #define DEVTRACE printf
#else
    #define DEVTRACE(...)
#endif

typedef enum {
    SmDirectionSend,
    SmDirectionRecv,
    SmDirectionBoth,
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
    BOOLEAN in_req; // TRUE if there's an outstanding req.
    SM_DIRECTION dir;
    SM_IO* io_tx;
    SM_IO* io_rx;

    // Byte counters for current req
    ULONG64 xferred_tx;
    ULONG64 xferred_rx;
    ULONG64 to_xfer;
    ULONG64 req_start_us;
} SM_CONN;

typedef struct _SM_THREAD {
    struct _SM_THREAD* next;
    HANDLE t;
    HANDLE iocp;
    CRITICAL_SECTION lock;
    ULONG64 xferred_tx; // sum of bytes tx'd by completed reqs.
    ULONG64 xferred_rx; // sum of bytes rx'd by completed reqs.
    SM_CONN* conns;
    ULONG numconns;
    ULONG64 reqlatency;
    ULONG64 numreqs;
} SM_THREAD;

// Variables for both client and service:
SM_THREAD* sm_threads = NULL;
int sm_nthread = 1;
int sm_iosize = 65535;  // 64KB default
int sm_sbuf = -1;
int sm_rbuf = -1;
BOOLEAN svcmode = FALSE;
int sm_ncpu = 0;

// Variables for client only:
SM_PEER* sm_peers = NULL;
ULONG64 sm_reqsize = 16000000;  // 16MB default
int sm_nsock = 1;
int sm_durationms = 0;
BOOLEAN sm_cleanup_time = FALSE;

// Variables for service only:
SERVICE_STATUS_HANDLE sm_svc_status_handle;
SERVICE_STATUS sm_svc_status;
SOCKADDR_INET sm_svcaddr = {0};
size_t sm_svcaddrlen = 0;

inline ULONG64 sm_curtime_us(void)
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
    return ticks * 1000000 / sm_perf_freq;
}

inline void sm_mean(ULONG64* to, ULONG64* to_n, ULONG64 from, ULONG64 from_n)
{
    // Merge two means.
    // "to" is a mean of "to_n" values; "from" is a mean of "from_n" values.
    *to = (*to * *to_n + from * from_n) / (*to_n + from_n);
    *to_n += from_n;
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
    peer->addrlen = SOCKADDR_SIZE(AF_INET6);

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

SM_CONN* sm_new_conn(SM_THREAD* thread, SOCKET sock, SM_DIRECTION dir)
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

    conn->io_tx = sm_new_io(SmDirectionSend);
    if (conn->io_tx == NULL) {
        printf("Failed to create new send IO\n");
        err = ERROR_NOT_ENOUGH_MEMORY;
        goto exit;
    }

    conn->io_rx = sm_new_io(SmDirectionRecv);
    if (conn->io_rx == NULL) {
        printf("Failed to create new recv IO\n");
        err = ERROR_NOT_ENOUGH_MEMORY;
        goto exit;
    }

    conn->sock = sock;
    conn->xferred_tx = 0;
    conn->xferred_rx = 0;
    conn->dir = dir;
    conn->in_req = FALSE;

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

SM_THREAD* sm_new_io_thread(LPTHREAD_START_ROUTINE fn)
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

    // Normally conns are deleted as they finish, but if there's an error
    // we may terminate early and still have some conns to delete here.
    while (thread->conns != NULL) {
        sm_del_conn(thread, thread->conns);
    }

    CloseHandle(thread->t);
    CloseHandle(thread->iocp);
    free(thread);
}

int sm_send(SM_CONN* conn, int offset, int numbytes)
{
    int err = NO_ERROR;

    DEVTRACE("sm_send offset=%d numbytes=%d\n", offset, numbytes);

    conn->io_tx->wsabuf.buf = conn->io_tx->buf + offset;
    conn->io_tx->wsabuf.len = numbytes;

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

exit:
    return err;
}

int sm_recv(SM_CONN* conn, int offset, int numbytes, int recvflags)
{
    int err = NO_ERROR;

    DEVTRACE("sm_recv offset=%d numbytes=%d\n", offset, numbytes);

    conn->io_rx->wsabuf.buf = conn->io_rx->buf + offset;
    conn->io_rx->wsabuf.len = numbytes;
    conn->io_rx->recvflags = recvflags;

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

exit:
    return err;
}

int sm_issue_req(SM_CONN* conn)
{
    int err = NO_ERROR;

    DEVTRACE("issue req\n");

    SM_REQ* req = (SM_REQ*)conn->io_tx->buf;
    switch (conn->dir) {
    case SmDirectionSend:
        req->dir = SmDirectionRecv;
        break;
    case SmDirectionRecv:
        req->dir = SmDirectionSend;
        break;
    case SmDirectionBoth:
        req->dir = SmDirectionBoth;
        break;
    }
    req->to_xfer = sm_reqsize;

    conn->to_xfer = req->to_xfer;

    conn->req_start_us = sm_curtime_us();

    conn->io_tx->to_xfer = sizeof(SM_REQ);
    err = sm_send(conn, 0, sizeof(SM_REQ));
    if (err != NO_ERROR) {
        goto exit;
    }

    // If we're receiving data as part of this req, get that started.
    if (conn->dir == SmDirectionRecv ||
        conn->dir == SmDirectionBoth) {

        conn->io_rx->to_xfer = (int)min(conn->io_rx->bufsize, req->to_xfer);
        err = sm_recv(conn, 0, conn->io_rx->to_xfer, 0);
        if (err != NO_ERROR) {
            goto exit;
        }
    }

exit:
    return err;
}

int sm_recv_req(SM_CONN* conn)
{
    int err = NO_ERROR;

    DEVTRACE("issue recv for req\n");

    conn->io_rx->to_xfer = sizeof(SM_REQ);
    err = sm_recv(conn, 0, sizeof(SM_REQ), MSG_WAITALL);
    if (err != NO_ERROR) {
        goto exit;
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

        #ifdef _DEBUG
            if (svcmode) {
                fflush(stdout);
            }
        #endif

        if (!GetQueuedCompletionStatus(
                thread->iocp, (DWORD*)&xferred, (ULONG_PTR*)&conn,
                (LPOVERLAPPED*)&io, timeout_ms)) {
            err = GetLastError();
            printf("GetQueuedCompletionStatus failed with %d\n", err);
            goto exit;
        }

        DEVTRACE("%s compl %d bytes\n",
                 io->dir == SmDirectionSend ? "tx" : "rx", xferred);

        if (xferred == 0) {

            // Peer disconnected.
            DEVTRACE("conn disconnected\n");
            sm_del_conn(thread, conn);

        } else if (!svcmode && !conn->in_req && io->dir == SmDirectionSend) {

            // Req sent.
            DEVTRACE("send req complete\n");
            conn->in_req = TRUE;

            if (conn->dir == SmDirectionSend || conn->dir == SmDirectionBoth) {
                io->xferred = 0;
                io->to_xfer = (int)min(io->bufsize, conn->to_xfer);
                err = sm_send(conn, 0, io->to_xfer);
                if (err != NO_ERROR) {
                    goto exit;
                }
            }
            // NB: We post the initial recv in sm_issue_req, so no need to post
            // it here.

        } else if (svcmode && !conn->in_req && io->dir == SmDirectionRecv) {

            // Req received.
            conn->in_req = TRUE;

            if (xferred != sizeof(SM_REQ)) {
                printf("Expected sizeof(SM_REQ) bytes but got %d\n", xferred);
                err = 1;
                goto exit;
            }
            SM_REQ* req = (SM_REQ*)conn->io_rx->buf;
            conn->to_xfer = req->to_xfer;
            conn->dir = req->dir;
            DEVTRACE("recv req complete, to_xfer=%llu, dir=%d\n",
                     conn->to_xfer, conn->dir);
            if (conn->dir == SmDirectionSend || conn->dir == SmDirectionBoth) {
                conn->io_tx->to_xfer =
                    (int)min(conn->io_tx->bufsize, conn->to_xfer);
                err = sm_send(conn, 0, conn->io_tx->to_xfer);
                if (err != NO_ERROR) {
                    goto exit;
                }
            }
            if (conn->dir == SmDirectionRecv || conn->dir == SmDirectionBoth) {
                conn->io_rx->to_xfer =
                    (int)min(conn->io_rx->bufsize, conn->to_xfer);
                err = sm_recv(conn, 0, conn->io_rx->to_xfer, 0);
                if (err != NO_ERROR) {
                    goto exit;
                }
            }

        } else {

            // Req payload [partly or fully] sent or received.

            ULONG64* conn_dir_xferred;
            if (io->dir == SmDirectionSend) {
                conn_dir_xferred = &conn->xferred_tx;
            } else {
                conn_dir_xferred = &conn->xferred_rx;
            }

            io->xferred += xferred;
            *conn_dir_xferred += xferred;
            DEVTRACE("now conn_dir_xferred %llu, io->xferred=%lu, io->to_xfer=%lu, conn->to_xfer=%llu\n",
                *conn_dir_xferred, io->xferred, io->to_xfer, conn->to_xfer);

            if (io->xferred < io->to_xfer) {
                // Continue current buf
                if (io->dir == SmDirectionSend) {
                    err = sm_send(conn, io->xferred, io->to_xfer - io->xferred);
                    if (err != NO_ERROR) {
                        goto exit;
                    }
                } else {
                    err = sm_recv(
                        conn, io->xferred, io->to_xfer - io->xferred, 0);
                    if (err != NO_ERROR) {
                        goto exit;
                    }
                }
            } else if (conn->to_xfer == 0 ||
                    *conn_dir_xferred < conn->to_xfer) {
                // New buf
                if (conn->to_xfer != 0 &&
                    io->to_xfer > (conn->to_xfer - *conn_dir_xferred)) {
                    // Partial buf fulfills req
                    io->to_xfer = (DWORD)(conn->to_xfer - *conn_dir_xferred);
                }
                io->xferred = 0;
                if (io->dir == SmDirectionSend) {
                    err = sm_send(conn, 0, io->to_xfer);
                    if (err != NO_ERROR) {
                        goto exit;
                    }
                } else {
                    err = sm_recv(conn, 0, io->to_xfer, 0);
                    if (err != NO_ERROR) {
                        goto exit;
                    }
                }
            } else {
                // Finished with [this direction of] req
                if (conn->dir != SmDirectionBoth ||
                    (conn->xferred_tx == conn->to_xfer &&
                     conn->xferred_rx == conn->to_xfer)) {

                    // Finished with req. Record it and either send/recv
                    // a new req or close the connection.

                    if (!svcmode) {
                        ULONG64 reqlatency =
                            sm_curtime_us() - conn->req_start_us;
                        sm_mean(&thread->reqlatency, &thread->numreqs,
                                reqlatency, 1);
                    }

                    thread->xferred_tx += conn->xferred_tx;
                    conn->xferred_tx = 0;
                    thread->xferred_rx += conn->xferred_rx;
                    conn->xferred_rx = 0;

                    if (sm_cleanup_time || (!svcmode && sm_durationms == 0)) {
                        DEVTRACE("shutting down conn\n");
                        shutdown(conn->sock, SD_BOTH);
                        sm_del_conn(thread, conn);
                    } else {
                        io->xferred = 0;
                        conn->in_req = FALSE;
                        if (svcmode) {
                            err = sm_recv_req(conn);
                            if (err != NO_ERROR) {
                                goto exit;
                            }
                        } else {
                            err = sm_issue_req(conn);
                            if (err != NO_ERROR) {
                                goto exit;
                            }
                        }
                    }
                }
            }
        }

        // TODO: synchronization issue here- first conn could finish and drop
        // counter to zero before second one increments counter, and we'd
        // terminate prematurely.
        if (thread->numconns == 0) {
            DEVTRACE("all conns done\n");
            break;
        }
    }

exit:
    return err;
}

int sm_connect_conn(SM_THREAD* thread, SM_PEER* peer)
{
    int err = NO_ERROR;
    SOCKET sock = INVALID_SOCKET;
    SM_CONN* conn = NULL;

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

    conn = sm_new_conn(thread, sock, peer->dir);
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

    err = sm_issue_req(conn);
    if (err != NO_ERROR) {
        printf("failed to send req\n");
        goto exit;
    }

exit:
    if (err != NO_ERROR) {
        if (conn != NULL) {
            sm_del_conn(thread, conn);
        }
        if (sock != INVALID_SOCKET) {
            closesocket(sock);
        }
    }
    return err;
}

SM_CONN* sm_accept_conn(SOCKET ls, SM_THREAD* thread)
{
    int err = NO_ERROR;
    SM_CONN* conn = NULL;

    SOCKET ss = accept(ls, NULL, NULL);
    if (ss == INVALID_SOCKET) {
        err = WSAGetLastError();
        printf("Accept failed with %d\n", err);
        goto exit;
    }

    DEVTRACE("Accepted connection\n");

    conn = sm_new_conn(thread, ss, SmDirectionBoth);
    if (conn == NULL) {
        err = ERROR_NOT_ENOUGH_MEMORY;
        printf("Failed to create new conn for accept socket\n");
        goto exit;
    }
    ss = INVALID_SOCKET; // conn owns socket now.

    err = sm_recv_req(conn);
    if (err != 0) {
        printf("failed to issue recv for req\n");
        goto exit;
    }

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

DWORD sm_service_io_fn(void* param)
{
    while (TRUE) {
        sm_io_loop((SM_THREAD*)param, INFINITE);
    }
    return 0;
}

DWORD sm_service_fn(void* param)
{
    UNREFERENCED_PARAMETER(param);
    int err = NO_ERROR;
    SOCKET ls = INVALID_SOCKET;
    SM_THREAD* thread = NULL;

    for (int i = 0; i < sm_nthread; i++) {
        sm_new_io_thread(sm_service_io_fn);
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

    if (sm_sbuf != -1) {
        if (setsockopt(
                ls, SOL_SOCKET, SO_SNDBUF, (char*)&sm_sbuf,
                sizeof(sm_sbuf)) == SOCKET_ERROR) {
            err = WSAGetLastError();
            printf("setsockopt(SO_SNDBUF) failed with %d\n", err);
            goto exit;
        }
    }

    if (sm_rbuf != -1) {
        if (setsockopt(
                ls, SOL_SOCKET, SO_RCVBUF, (char*)&sm_sbuf,
                sizeof(sm_sbuf)) == SOCKET_ERROR) {
            err = WSAGetLastError();
            printf("setsockopt(SO_RCVBUF) failed with %d\n", err);
            goto exit;
        }
    }

    if (bind(ls, (SOCKADDR*)&sm_svcaddr, (int)sm_svcaddrlen) == SOCKET_ERROR) {
        printf("bind failed with %d\n", WSAGetLastError());
        goto exit;
    }

    if (listen(ls, SOMAXCONN) == SOCKET_ERROR) {
        printf("listen failed with %d\n", WSAGetLastError());
        goto exit;
    }


    printf(
        "Started sockmeter service.\n\n"
        "cpus: %d\n"
        "threads: %d\n"
        "listenport: %d\n",
        sm_ncpu, sm_nthread, ntohs(SS_PORT(&sm_svcaddr)));

    thread = sm_threads;
    while (TRUE) {

        // TODO: how to break out of accept when service stops?
        // For now, just break out the next time we return from accept.
        if (sm_cleanup_time) {
            goto exit;
        }

        SM_CONN* conn = sm_accept_conn(ls, thread);
        if (conn == NULL) {
            goto exit;
        }
        thread = thread->next;
        if (thread == NULL) {
            thread = sm_threads;
        }
    }

exit:
    if (ls != INVALID_SOCKET) {
        closesocket(ls);
    }
    return err;
}

DWORD sm_client_io_fn(void* param)
{
    return sm_io_loop((SM_THREAD*)param, 5000);
}

void sm_client(void)
{
    int err = NO_ERROR;
    SM_THREAD* thread = NULL;
    SM_PEER* peer = NULL;

    for (int i = 0; i < sm_nthread; i++) {
        thread = sm_new_io_thread(sm_client_io_fn);
        if (thread == NULL) {
            return;
        }
    }

    printf("Testing...\n");

    ULONG64 t_start_us = sm_curtime_us();

    // Assign conns to threads and peers round-robin.

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

    if (sm_durationms > 0) {
        err = SleepEx(sm_durationms, FALSE);
        sm_cleanup_time = TRUE;
    }

    thread = sm_threads;
    while (thread != NULL) {
        WaitForSingleObject(thread->t, INFINITE);
        thread = thread->next;
    }

    ULONG64 t_end_us = sm_curtime_us();
    ULONG64 t_elapsed_us = t_end_us - t_start_us;

    printf("Finished.\n");

    ULONG64 xferred_tx = 0;
    ULONG64 xferred_rx = 0;
    ULONG64 reqlatency = 0;
    ULONG64 numreqs = 0;
    thread = sm_threads;
    while (thread != NULL) {
        if (thread->conns != NULL) {
            printf("unexpected: thread still has active conns\n");
        }
        xferred_tx += thread->xferred_tx;
        xferred_rx += thread->xferred_rx;
        sm_mean(&reqlatency, &numreqs, thread->reqlatency, thread->numreqs);
        thread = thread->next;
    }
    printf(
        "\ncpus: %d\n"
        "threads: %d\n"
        "sockets: %d\n"
        "runtime_ms: %llu\n"
        "req_bytes: %llu\n"
        "req_count: %llu\n"
        "req_avg_us: %llu\n"
        "tx_bytes: %llu\n"
        "tx_Mbps: %llu\n"
        "rx_bytes: %llu\n"
        "rx_Mbps: %llu\n",
        sm_ncpu,
        sm_nthread,
        sm_nsock,
        t_elapsed_us / 1000,
        sm_reqsize,
        numreqs,
        reqlatency,
        xferred_tx,
        (xferred_tx * 8) / (t_elapsed_us),
        xferred_rx,
        (xferred_rx * 8) / (t_elapsed_us));
}

int realmain(int argc, wchar_t** argv)
{
    int err = 0;
    BOOLEAN need_wsacleanup = FALSE;
    WSADATA wd = {0};
    int numpeers = 0;
    BOOLEAN nthread_passed = FALSE;

    if (argc == 1) {
        printf(USAGE);
        goto exit;
    } else if (argc == 2 && !wcscmp(argv[1], L"-v")) {
        printf("%s\n", VERSION);
        goto exit;
    }

    {
        // Get info on the CPU. Here we use GetLogicalProcessorInformationEx
        // instead of GetSystemInfo so we can get a full count of logical
        // processors rather than just the count of logical processors in
        // sockmeter's assigned processor group.
        //
        // TODO: use RelationNumaNodeEx and build a list of nodes rather than
        // just counting the processors.
        DWORD cpuinfo_len = 0;
        GetLogicalProcessorInformationEx(RelationGroup, NULL, &cpuinfo_len);
        SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX* cpuinfo = malloc(cpuinfo_len);
        if (cpuinfo == NULL) {
            err = ERROR_NOT_ENOUGH_MEMORY;
            printf("failed to allocate cpuinfo\n");
            goto exit;
        }
        if (!GetLogicalProcessorInformationEx(
                RelationGroup, cpuinfo, &cpuinfo_len)) {
            err = GetLastError();
            printf("GetLogicalProcessorInformationEx failed with %d\n", err);
            free(cpuinfo);
            goto exit;
        }
        for (int i = 0; i < cpuinfo->Group.ActiveGroupCount; i++) {
            sm_ncpu += cpuinfo->Group.GroupInfo[i].MaximumProcessorCount;
        }
        free(cpuinfo);
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
        if (argsleft >= 1 &&
                (!wcscmp(*name, L"-svc") ||
                 !wcscmp(*name, L"-d"))) {
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
            nthread_passed = TRUE;
            av++; ac++;
        } else if (argsleft >= 1 && !wcscmp(*name, L"-reqsize")) {
            sm_reqsize = _wtoi64(*av);
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
        } else if (argsleft >= 2 && !wcscmp(*name, L"-tx")) {
            if (sm_new_peer(*av, *(av + 1), SmDirectionSend) == NULL) {
                printf("Failed to parse \"-tx %ls %ls\"\n", *av, *(av + 1));
                err = ERROR_INVALID_PARAMETER;
                goto exit;
            }
            numpeers++;
            av += 2; ac += 2;
        } else if (argsleft >= 2 && !wcscmp(*name, L"-rx")) {
            if (sm_new_peer(*av, *(av + 1), SmDirectionRecv) == NULL) {
                printf("Failed to parse \"-rx %ls %ls\"\n", *av, *(av + 1));
                err = ERROR_INVALID_PARAMETER;
                goto exit;
            }
            numpeers++;
            av += 2; ac += 2;
        } else if (argsleft >= 2 && !wcscmp(*name, L"-txrx")) {
            if (sm_new_peer(*av, *(av + 1), SmDirectionBoth) == NULL) {
                printf("Failed to parse \"-txrx %ls %ls\"\n", *av, *(av + 1));
                err = ERROR_INVALID_PARAMETER;
                goto exit;
            }
            numpeers++;
            av += 2; ac += 2;
        } else {
            DEVTRACE("realmain: invalid parameter, argsleft=%d\n", argsleft);
            printf(USAGE);
            err = ERROR_INVALID_PARAMETER;
            goto exit;
        }
    }

    if (svcmode && numpeers > 0) {
        printf("ERROR: cannot pass both -svc and (-tx or -rx or -txrx).\n");
        err = ERROR_INVALID_PARAMETER;
        goto exit;
    }

    if (sm_iosize == 0) {
        printf("ERROR: cannot set -iosize to 0.\n");
        err = ERROR_INVALID_PARAMETER;
        goto exit;
    }

    if (sm_iosize < sizeof(SM_REQ)) {
        printf("iosize must be at least %lu\n", (int)sizeof(SM_REQ));
        err = ERROR_INVALID_PARAMETER;
        goto exit;
    }

    if (svcmode) {
        if (!nthread_passed) {
            sm_nthread = min(sm_ncpu, 64);
        }
        sm_service_fn(NULL);
    } else {
        if (numpeers == 0) {
            printf("ERROR: Must pass (-tx or -rx or -txrx) at least once\n");
            err = ERROR_INVALID_PARAMETER;
            goto exit;
        }
        if (sm_nthread > sm_nsock) {
            sm_nsock = sm_nthread;
        }
        if (numpeers > sm_nsock) {
            sm_nsock = numpeers;
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

void WINAPI svc_ctrl(DWORD code)
{
    printf("svc_ctrl, code = %d\n", code);
    fflush(stdout);
    if (code == SERVICE_CONTROL_STOP) {
        sm_cleanup_time = TRUE;
        sm_svc_status.dwCurrentState = SERVICE_STOP_PENDING;
        sm_svc_status.dwControlsAccepted = SERVICE_ACCEPT_STOP;
        sm_svc_status.dwWin32ExitCode = NO_ERROR;
        SetServiceStatus(sm_svc_status_handle, &sm_svc_status);
    }
}

void WINAPI svc_main(DWORD argc, wchar_t** argv)
{
    sm_svc_status_handle = RegisterServiceCtrlHandlerW(L"sockmeter", svc_ctrl);
    sm_svc_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    sm_svc_status.dwControlsAccepted = SERVICE_ACCEPT_STOP;

    // We're not really set up yet. But we'll be fast...
    // Report SERVICE_START_PENDING here with an appropriate
    // dwWaitHint and only claim to be RUNNING once we really are,
    // if that becomes necessary. (Also make sure to not indicate
    // dwControlsAccepted=SERVICE_ACCEPT_STOP while we are in
    // SERVICE_START_PENDING state).

    sm_svc_status.dwCurrentState = SERVICE_RUNNING;
    sm_svc_status.dwWin32ExitCode = NO_ERROR;
    SetServiceStatus(sm_svc_status_handle, &sm_svc_status);

    #ifdef _DEBUG
    FILE* f;
    freopen_s(&f, "C:\\sockmeter-svc-log.txt", "w", stdout);
    #endif

    realmain(argc, argv);

    printf("svc_main exiting\n");
    fflush(stdout);

    sm_svc_status.dwCurrentState = SERVICE_STOPPED;
    sm_svc_status.dwWin32ExitCode = NO_ERROR;
    SetServiceStatus(sm_svc_status_handle, &sm_svc_status);
}

int __cdecl wmain(int argc, wchar_t** argv)
{
    int err = NO_ERROR;
    if (argc == 2 && !wcscmp(argv[1], L"-d")) {
        SERVICE_TABLE_ENTRYW svctable[] = {{L"", svc_main}, {NULL, NULL}};
        if (!StartServiceCtrlDispatcherW(svctable)) {
            err = GetLastError();
            if (err == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) {
                printf("Don't pass -d from command line! See help text and use sc.exe.\n");
            }
        }
    } else {
        err = realmain(argc, argv);
    }
    return err;
}
