/*
Sockmeter: a Windows TCP performance measurement tool.

Compared to iperf: Optimized for Windows with IOCP.

Compared to ntttcp: Allows the thread count and socket count to be
separately configured; no need to re-run the service on each execution;
the service uses a single port number.

TODO:
-add metric: avg packet size
-add metric: cpu%
-write stats to json
-iofrag option (pass multiple wsabufs to WSASend/WSARecv)
-reuseconn option (default true; whether to reuse conns for new reqs)
-consider SO_LINGER/SO_DONTLINGER
-Currently the service side thread count is min(64, numProc).
    Consider creating a number of threads equal to the number of
    RSS processors and assigning conns to threads based on the output of
    SIO_QUERY_RSS_PROCESSOR_INFO rather than round-robin.
-cmdline args to force v4/6 when using hostnames
-allow a single service instance to listen on multiple ports

REFERENCE:
-service reg path: hklm\system\currentcontrolset\services\sockmeter
-service log (only written by debug build): c:\sockmeter-svc-log.txt
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
#include <shellapi.h>

#define VERSION "3.1.0"

#define USAGE \
"\nsockmeter version " VERSION "\n" \
"\n" \
"Measures network performance.\n" \
"Sockmeter client connects to one or more sockmeter services.\n" \
"On each connection, the client issues a series of requests\n" \
"to send and/or receive data.\n" \
"\n" \
"Usage:\n" \
"   sockmeter -v\n" \
"       Print the version.\n" \
"   sockmeter [client_args]\n" \
"       Run client.\n" \
"   sockmeter -svc [p]\n" \
"       Start service, listening on port p.\n" \
"   sockmeter -delsvc\n" \
"       Delete existing sockmeter service.\n" \
"   sockmeter -listen [p]\n" \
"       Like -svc, but run in current shell rather than a service process.\n" \
"\n" \
"[client_args]:\n" \
"   -tx [h] [p]:\n" \
"   -rx [h] [p]:\n" \
"   -txrx [h] [p]:\n" \
"         Connect to host h at port p. h can be a hostname or IP address.\n" \
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
"Example:\n" \
"   sockmeter -svc 30000\n" \
"   sockmeter -tx localhost 30000 -rx localhost 30000 -nsock 20\n" \
"   sockmeter -delsvc\n" \
"\n"

#ifdef _DEBUG
    #define DEVTRACE printf
#else
    #define DEVTRACE(...)
#endif

#include "stats.h"

typedef enum {
    SmDirectionSend,
    SmDirectionRecv,
    SmDirectionBoth,
} SmDirection;

#pragma pack(push,1)
typedef struct {
    SmDirection dir;
    ULONG64 to_xfer;
} SmRequest;
typedef struct {
#define RESP_UNUSED_VALUE 13
    ULONG64 unused;
} SmResponse;
#pragma pack(pop)

typedef struct _SmPeer {
    struct _SmPeer* next;
    SOCKADDR_INET addr;
    int addrlen;
    SmDirection dir;
} SmPeer;

typedef struct _SmIo {
    WSAOVERLAPPED ov; // Assumed to be the first field.
    WSABUF wsabuf;
    DWORD recvflags;
    SmDirection dir;
    DWORD xferred;
    DWORD to_xfer; // Usually equal to bufsize.
    char* buf;
    int bufsize;
} SmIo;

typedef enum {
    SmConnStateRequest,
    SmConnStatePayload,
    SmConnStateResponse
} SmConnState;

typedef struct _SmConn {
    struct _SmConn* next;
    SOCKET sock;
    SmConnState state;
    SmDirection dir;
    SmIo* io_tx;
    SmIo* io_rx;

    // Values pertaining to current request's payload.
    ULONG64 xferred_tx;
    ULONG64 xferred_rx;
    ULONG64 to_xfer;
    ULONG64 req_start_us;
} SmConn;

typedef struct _SmIoThread {
    struct _SmIoThread* next;
    HANDLE t;
    HANDLE iocp;
    CRITICAL_SECTION lock;
    ULONG64 xferred_tx; // sum of bytes tx'd by completed reqs.
    ULONG64 xferred_rx; // sum of bytes rx'd by completed reqs.
    SmConn* conns;
    ULONG numconns;
    ULONG64 numreqs;
    SmStat reqlatency;
} SmIoThread;

// Variables for both client and service:
SmIoThread* sm_threads = NULL;
int sm_nthread = 1;
int sm_iosize = 65535;  // 64KB default
int sm_sbuf = -1;
int sm_rbuf = -1;
BOOLEAN svcmode = FALSE;
int sm_ncpu = 0;

// Variables for client only:
SmPeer* sm_peers = NULL;
ULONG64 sm_reqsize = 16000000;  // 16MB default
int sm_nsock = 1;
int sm_durationms = 0;
BOOLEAN sm_cleanup_time = FALSE;

// Variables for service only:
SERVICE_STATUS_HANDLE sm_svc_status_handle;
SERVICE_STATUS sm_svc_status;
SOCKADDR_INET sm_svcaddr = {0};
size_t sm_svcaddrlen = 0;
HANDLE sm_accept_iocp = NULL;
GUID acceptex_guid = WSAID_ACCEPTEX;
LPFN_ACCEPTEX AcceptExFn;
#define SM_ACCEPT_KEY_CLEANUP_TIME 1
#define SM_SERVICE_NAME L"sockmeter"

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

SmPeer* sm_new_peer(wchar_t* host, wchar_t* port, SmDirection dir)
{
    int err = NO_ERROR;
    SmPeer* peer = NULL;
    ADDRINFOW hints = {0};
    ADDRINFOW* res = NULL;

    peer = malloc(sizeof(SmPeer));
    if (peer == NULL) {
        printf("Failed to allocate SmPeer\n");
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

void sm_del_peer(SmPeer* peer)
{
    SmPeer** p = &sm_peers;
    while (*p != peer) {
        p = &((*p)->next);
    }
    *p = peer->next;

    free(peer);
}

SmIo* sm_new_io(SmDirection dir)
{
    int err = NO_ERROR;
    SmIo* io = NULL;

    io = malloc(sizeof(SmIo));
    if (io == NULL) {
        printf("Failed to allocate SmIo\n");
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

void sm_del_io(SmIo* io)
{
    // TODO: Check HasOverlappedIoCompleted and cancel/wait for completion
    // if necessary.
    WSACloseEvent(io->ov.hEvent);
    free(io->buf);
    free(io);
}

SmConn* sm_new_conn(SmIoThread* thread, SOCKET sock, SmDirection dir)
{
    int err = NO_ERROR;
    SmConn* conn = NULL;

    conn = malloc(sizeof(SmConn));
    if (conn == NULL) {
        printf("Failed to allocate SmConn\n");
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
    conn->state = SmConnStateRequest;

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

void sm_del_conn(SmIoThread* thread, SmConn* conn)
{
    EnterCriticalSection(&thread->lock);
    SmConn** c = &(thread->conns);
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

SmIoThread* sm_new_io_thread(LPTHREAD_START_ROUTINE fn)
{
    int err = NO_ERROR;
    SmIoThread* thread = NULL;

    thread = malloc(sizeof(SmIoThread));
    if (thread == NULL) {
        printf("Failed to allocate SmIoThread\n");
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
    sm_stat_init(&thread->reqlatency);

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

void sm_del_io_thread(SmIoThread* thread)
{
    // This is called from the main thread on termination, and we assume
    // the SmIoThread's thread is already terminated.

    SmIoThread** t = &sm_threads;
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

int sm_send(SmConn* conn, int offset, int numbytes)
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

int sm_recv(SmConn* conn, int offset, int numbytes, int recvflags)
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

int sm_issue_req(SmConn* conn)
{
    int err = NO_ERROR;

    DEVTRACE("issue req\n");

    SmRequest* req = (SmRequest*)conn->io_tx->buf;
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

    conn->io_tx->to_xfer = sizeof(SmRequest);
    err = sm_send(conn, 0, sizeof(SmRequest));
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

int sm_recv_req(SmConn* conn)
{
    int err = NO_ERROR;

    DEVTRACE("issue recv for req\n");

    conn->io_rx->to_xfer = sizeof(SmRequest);
    err = sm_recv(conn, 0, sizeof(SmRequest), MSG_WAITALL);
    if (err != NO_ERROR) {
        goto exit;
    }

exit:
    return err;
}

int sm_issue_resp(SmConn* conn)
{
    int err = NO_ERROR;

    DEVTRACE("issue response\n");

    SmResponse* resp = (SmResponse*)conn->io_tx->buf;
    resp->unused = RESP_UNUSED_VALUE;

    conn->io_tx->to_xfer = sizeof(SmResponse);
    err = sm_send(conn, 0, sizeof(SmResponse));
    if (err != NO_ERROR) {
        goto exit;
    }

exit:
    return err;
}

int sm_recv_resp(SmConn* conn)
{
    int err = NO_ERROR;

    DEVTRACE("issue recv for response\n");

    conn->io_rx->to_xfer = sizeof(SmResponse);
    err = sm_recv(conn, 0, sizeof(SmResponse), MSG_WAITALL);
    if (err != NO_ERROR) {
        goto exit;
    }

exit:
    return err;
}

int sm_io_loop(SmIoThread* thread, ULONG timeout_ms)
{
    // Loop on GetQueuedCompletionStatus, reposting IOs or shutting down
    // conns as appropriate.

    int err = NO_ERROR;
    int xferred = 0;
    SmConn* conn = NULL;
    SmIo* io = NULL;

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

        } else if (conn->state == SmConnStateResponse) {

            // Response sent/received.

            conn->state = SmConnStateRequest;

            if (svcmode) {
                DEVTRACE("send response complete\n");
            } else {
                DEVTRACE("recv response complete\n");

                // Record stats for this request.
                ULONG64 latency = sm_curtime_us() - conn->req_start_us;
                sm_stat_add(&thread->reqlatency, latency);
                thread->xferred_tx += conn->xferred_tx;
                thread->xferred_rx += conn->xferred_rx;
            }

            conn->xferred_tx = 0;
            conn->xferred_rx = 0;

            // Shut down or do the next request.

            if (sm_cleanup_time || (!svcmode && sm_durationms == 0)) {
                DEVTRACE("shutting down conn\n");
                shutdown(conn->sock, SD_BOTH);
                sm_del_conn(thread, conn);
            } else {
                io->xferred = 0;
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

        } else if (!svcmode &&
                   conn->state == SmConnStateRequest &&
                   io->dir == SmDirectionSend) {

            // Request sent.
            DEVTRACE("send req complete\n");
            conn->state = SmConnStatePayload;

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

        } else if (svcmode &&
                   conn->state == SmConnStateRequest &&
                   io->dir == SmDirectionRecv) {

            // Request received.
            conn->state = SmConnStatePayload;

            if (xferred != sizeof(SmRequest)) {
                printf("Expected sizeof(SmRequest) bytes but got %d\n", xferred);
                err = 1;
                goto exit;
            }
            SmRequest* req = (SmRequest*)conn->io_rx->buf;
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

            // Payload [partly or fully] sent or received.

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
                // Finished with [this direction of] payload.
                if (conn->dir != SmDirectionBoth ||
                    (conn->xferred_tx == conn->to_xfer &&
                     conn->xferred_rx == conn->to_xfer)) {

                    // Finished with both directions of payload. Process
                    // the response.

                    conn->state = SmConnStateResponse;

                    if (svcmode) {
                        err = sm_issue_resp(conn);
                        if (err != NO_ERROR) {
                            goto exit;
                        }
                    } else {
                        err = sm_recv_resp(conn);
                        if (err != NO_ERROR) {
                            goto exit;
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

int sm_connect_conn(SmIoThread* thread, SmPeer* peer)
{
    int err = NO_ERROR;
    SOCKET sock = INVALID_SOCKET;
    SmConn* conn = NULL;

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

    opt = 1;
    if (setsockopt(
            sock, IPPROTO_TCP, TCP_NODELAY, (char*)&opt, sizeof(opt))
                == SOCKET_ERROR) {
        err = WSAGetLastError();
        printf("setsockopt(TCP_NODELAY) failed with %d\n", err);
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

SmConn* sm_accept_conn(SOCKET ls, SmIoThread* thread)
{
    int err = NO_ERROR;
    SmConn* conn = NULL;

    SOCKET ss = WSASocket(
        AF_INET6, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
    if (ls == INVALID_SOCKET) {
        printf("socket failed with %d\n", WSAGetLastError());
        goto exit;
    }

    OVERLAPPED ov = {0};
    DWORD xferred = 0;
    char addrspace[2 * sizeof(SOCKADDR_INET) + 32];
    if (!AcceptExFn(
        ls, ss, addrspace, 0, sizeof(addrspace) / 2, sizeof(addrspace) / 2,
        &xferred, &ov)) {
        err = WSAGetLastError();
        if (err != WSA_IO_PENDING) {
            printf("AcceptEx failed with %d\n", err);
            goto exit;
        } else {
            err = NO_ERROR;
        }
    }

    LPOVERLAPPED pov = NULL;
    ULONG_PTR key = 0;
    if (!GetQueuedCompletionStatus(
            sm_accept_iocp, &xferred, &key, &pov, INFINITE)) {
        err = GetLastError();
        printf("GetQueuedCompletionStatus (accept iocp) failed with %d\n", err);
        goto exit;
    }
    if (key == SM_ACCEPT_KEY_CLEANUP_TIME) {
        err = 1;
        goto exit;
    }

    if (setsockopt(ss, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT,
                   (char*)&ls, sizeof(ls)) == SOCKET_ERROR) {
        err = WSAGetLastError();
        printf("setsockopt(SO_UPDATE_ACCEPT_CONTEXT) failed with %d\n", err);
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
        sm_io_loop((SmIoThread*)param, INFINITE);
    }
    return 0;
}

DWORD sm_service(void* param)
{
    UNREFERENCED_PARAMETER(param);
    int err = NO_ERROR;
    SOCKET ls = INVALID_SOCKET;
    SmIoThread* thread = NULL;

    sm_accept_iocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
    if (sm_accept_iocp == NULL) {
        err = GetLastError();
        printf("CreateIoCompletionPort failed with %d\n", err);
        goto exit;
    }

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

    opt = 1;
    if (setsockopt(
            ls, IPPROTO_TCP, TCP_NODELAY, (char*)&opt, sizeof(opt))
                == SOCKET_ERROR) {
        err = WSAGetLastError();
        printf("setsockopt(TCP_NODELAY) failed with %d\n", err);
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

    if (CreateIoCompletionPort(
            (HANDLE)ls, sm_accept_iocp, (ULONG_PTR)NULL, 0) == NULL) {
        err = GetLastError();
        printf("Associating listen sock to iocp failed with %d\n", err);
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

    DWORD bytes_ret = 0;
    err = WSAIoctl(ls, SIO_GET_EXTENSION_FUNCTION_POINTER,
                   &acceptex_guid, sizeof(acceptex_guid),
                   &AcceptExFn, sizeof(AcceptExFn),
                   &bytes_ret, NULL, NULL);
    if (err == SOCKET_ERROR) {
        err = WSAGetLastError();
        printf("WSAIoctl(SIO_GET_EXTENSION_FUNCTION_POINTER, AcceptEx) failed"
               " with %d", err);
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
        SmConn* conn = sm_accept_conn(ls, thread);
        if (conn == NULL) {
            goto exit;
        }
        thread = thread->next;
        if (thread == NULL) {
            thread = sm_threads;
        }
    }

exit:
    // TODO: join all threads before exit
    if (ls != INVALID_SOCKET) {
        closesocket(ls);
    }
    if (sm_accept_iocp != NULL) {
        CloseHandle(sm_accept_iocp);
    }
    return err;
}

DWORD sm_client_io_fn(void* param)
{
    return sm_io_loop((SmIoThread*)param, 5000);
}

void sm_client(void)
{
    int err = NO_ERROR;
    SmIoThread* thread = NULL;
    SmPeer* peer = NULL;

    for (int i = 0; i < sm_nthread; i++) {
        thread = sm_new_io_thread(sm_client_io_fn);
        if (thread == NULL) {
            return;
        }
    }

    printf("Running... ");

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
    SmStat* reqlatency = malloc(sizeof(SmStat));
    if (reqlatency == NULL) {
        printf("Failed to allocate memory for calculating stats!\n");
        return;
    }
    sm_stat_init(reqlatency);

    // Merge the per-thread stats.
    thread = sm_threads;
    while (thread != NULL) {
        if (thread->conns != NULL) {
            printf("unexpected: thread still has active conns\n");
        }
        xferred_tx += thread->xferred_tx;
        xferred_rx += thread->xferred_rx;
        sm_stat_merge(reqlatency, &thread->reqlatency);
        thread = thread->next;
    }

    printf(
        "\ncpus: %d\n"
        "threads: %d\n"
        "sockets: %d\n"
        "runtime_ms: %llu\n"
        "io_bytes: %d\n"
        "req_bytes: %llu\n"
        "req_count: %llu\n"
        "reqlatency_avg_us: %llu\n"
        "reqlatency_p99_us: %llu\n"
        "reqlatency_p100_us: %llu\n"
        "tx_bytes: %llu\n"
        "tx_Mbps: %llu\n"
        "rx_bytes: %llu\n"
        "rx_Mbps: %llu\n",
        sm_ncpu,
        sm_nthread,
        sm_nsock,
        t_elapsed_us / 1000,
        sm_iosize,
        sm_reqsize,
        reqlatency->count,
        reqlatency->mean,
        sm_stat_percentile(reqlatency, 99),
        reqlatency->max,
        xferred_tx,
        (xferred_tx * 8) / (t_elapsed_us),
        xferred_rx,
        (xferred_rx * 8) / (t_elapsed_us));

    free(reqlatency);
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
                (!wcscmp(*name, L"-listen") ||
                 !wcscmp(*name, L"-svclisten"))) {
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

    if (sm_iosize < sizeof(SmRequest)) {
        printf("iosize must be at least %lu\n", (int)sizeof(SmRequest));
        err = ERROR_INVALID_PARAMETER;
        goto exit;
    }

    if (svcmode) {
        if (!nthread_passed) {
            sm_nthread = min(sm_ncpu, 64);
        }
        sm_service(NULL);
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
        sm_del_io_thread(sm_threads);
    }

    while (sm_peers != NULL) {
        sm_del_peer(sm_peers);
    }

    if (need_wsacleanup) {
        WSACleanup();
    }

    return err;
}

int sm_start_svc(int argc, wchar_t** argv)
{
    // NB: assumes argc == 3

    int err = NO_ERROR;
    SC_HANDLE svc_handle = NULL;
    SC_HANDLE scm_handle = NULL;
    SERVICE_STATUS svc_status = {0};
    // args for starting the service are "-svc [p]"; change this to the
    // args expected by the service: "-svclisten [p]".
    wchar_t abspath[MAX_PATH + 2];
    wchar_t* modified_argv[3] = {abspath, L"-svclisten", argv[2]};
    wchar_t* cmdline = NULL;

    abspath[0] = L'\"'; // wrap in quotes in case of spaces in path.
    if (!GetModuleFileName(NULL, abspath + 1, MAX_PATH)) {
        err = GetLastError();
        printf("GetModuleFileName failed with %d\n", err);
        goto exit;
    }
    wcscat_s(abspath, MAX_PATH + 2, L"\"");

    scm_handle = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (scm_handle == NULL) {
        err = GetLastError();
        if (err == ERROR_ACCESS_DENIED) {
            printf("ERROR_ACCESS_DENIED- must start service as admin.\n");
        } else {
            printf("OpenSCManager failed with %d\n", err);
        }
        goto exit;
    }

    svc_handle = OpenService(scm_handle, SM_SERVICE_NAME, SERVICE_ALL_ACCESS);
    if (svc_handle == NULL) {
        err = GetLastError();
        if (err == ERROR_SERVICE_DOES_NOT_EXIST) {

            // NB- this cmdline is used for autostart. For demand start
            // the args passed to StartService are used instead.
            size_t cmdline_len = 0;
            for (int i = 0; i < argc; i++) {
                cmdline_len += wcslen(modified_argv[i]) + 1;
            }
            cmdline = malloc(cmdline_len * sizeof(wchar_t));
            if (cmdline == NULL) {
                printf("Could not allocate cmdline for CreateService\n");
                err = ERROR_NOT_ENOUGH_MEMORY;
                goto exit;
            }
            cmdline[0] = L'\0';
            for (int i = 0; i < argc - 1; i++) {
                wcscat_s(cmdline, cmdline_len, modified_argv[i]);
                wcscat_s(cmdline, cmdline_len, L" ");
            }
            wcscat_s(cmdline, cmdline_len, modified_argv[argc - 1]);

            svc_handle = CreateService(
                scm_handle, SM_SERVICE_NAME, SM_SERVICE_NAME,
                SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
                SERVICE_AUTO_START, SERVICE_ERROR_NORMAL, cmdline,
                NULL, NULL, NULL, L"NT AUTHORITY\\LocalService", NULL);
            if (svc_handle == NULL) {
                err = GetLastError();
                printf("CreateService failed with %d\n", err);
                goto exit;
            }
        } else {
            printf("OpenService failed with %d\n", err);
            goto exit;
        }
    }

    if (!QueryServiceStatus(svc_handle, &svc_status)) {
        err = GetLastError();
        printf("QueryServiceStatus failed with %d\n", err);
        goto exit;
    }

    if (svc_status.dwCurrentState == SERVICE_STOPPED) {
        printf("Starting service.\n");
        if (!StartService(svc_handle, argc - 1, modified_argv + 1)) {
            err = GetLastError();
            printf("StartService failed with %d\n", err);
            goto exit;
        }
    } else if (svc_status.dwCurrentState == SERVICE_RUNNING) {
        printf("Sockmeter service is already running.\n");
        printf("Run -delsvc first if you want to start with a new configuration.\n");
        err = 1;
        goto exit;
    }

exit:
    if (cmdline != NULL) {
        free(cmdline);
    }
    if (svc_handle != NULL) {
        CloseServiceHandle(svc_handle);
    }
    if (scm_handle != NULL) {
        CloseServiceHandle(scm_handle);
    }
    return err;
}

int sm_del_svc(void)
{
    int err = NO_ERROR;
    SC_HANDLE svc_handle = NULL;
    SC_HANDLE scm_handle = NULL;
    SERVICE_STATUS svc_status = {0};

    scm_handle = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (scm_handle == NULL) {
        err = GetLastError();
        if (err == ERROR_ACCESS_DENIED) {
            printf("ERROR_ACCESS_DENIED- must delete service as admin.\n");
        } else {
            printf("OpenSCManager failed with %d\n", err);
        }
        goto exit;
    }

    svc_handle = OpenService(scm_handle, SM_SERVICE_NAME, SERVICE_ALL_ACCESS);
    if (svc_handle == NULL) {
        err = GetLastError();
        if (err == ERROR_SERVICE_DOES_NOT_EXIST) {
            printf("Sockmeter service is not running.\n");
            err = NO_ERROR;
        } else {
            printf("OpenService failed with %d\n", err);
        }
        goto exit;
    }

    if (!ControlService(svc_handle, SERVICE_CONTROL_STOP, &svc_status)) {
        err = GetLastError();
        if (err == ERROR_SERVICE_NOT_ACTIVE) {
            // already stopped.
            err = NO_ERROR;
            goto delsvc;
        }
        printf("ControlService failed with %d\n", err);
    }

    while (QueryServiceStatus(svc_handle, &svc_status)) {
        if (svc_status.dwCurrentState != SERVICE_STOP_PENDING) {
            break;
        }
        Sleep(500);
    }

    if (svc_status.dwCurrentState != SERVICE_STOPPED) {
        printf("Failed to stop sockmeter service.\n");
        err = 1;
        goto exit;
    }

delsvc:
    if (!DeleteService(svc_handle)) {
        err = GetLastError();
        printf("DeleteService failed with %d\n", err);
        goto exit;
    }

    printf("Stopped sockmeter service.\n");

exit:
    if (svc_handle != NULL) {
        CloseServiceHandle(svc_handle);
    }
    if (scm_handle != NULL) {
        CloseServiceHandle(scm_handle);
    }
    return err;
}

void WINAPI svc_ctrl(DWORD code)
{
    printf("svc_ctrl, code = %d\n", code);
    if (code == SERVICE_CONTROL_STOP) {
        sm_cleanup_time = TRUE;
        sm_svc_status.dwCurrentState = SERVICE_STOP_PENDING;
        sm_svc_status.dwControlsAccepted = SERVICE_ACCEPT_STOP;
        sm_svc_status.dwWin32ExitCode = NO_ERROR;
        SetServiceStatus(sm_svc_status_handle, &sm_svc_status);

        if (!PostQueuedCompletionStatus(
                sm_accept_iocp, 0, SM_ACCEPT_KEY_CLEANUP_TIME, NULL)) {
            int err = GetLastError();
            printf("PostQueuedCompletionStatus failed with %d\n", err);
        }
    }
    fflush(stdout);
}

void WINAPI svc_main(DWORD argc, wchar_t** argv)
{
    sm_svc_status_handle =
        RegisterServiceCtrlHandlerW(SM_SERVICE_NAME, svc_ctrl);
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

    // Begin atrocity: if the service starts by virtue of our StartService
    // call, then the argc/argv passed to svc_main are the same as those
    // passed to wmain. But if we start at boot by virtue of being an
    // auto-start service (or by starting the service with "net start sockmeter"
    // then the ImagePath args from the registry are passed to wmain but
    // just a single arg with the name of the service ("sockmeter") is
    // passed to svc_main. So, look up the command line with GetCommandLine
    // and use that to populate our own argc/argv to pass to realmain.
    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);
    int my_argc = 0;
    wchar_t** my_argv = CommandLineToArgvW(GetCommandLine(), &my_argc);
    // End atrocity.

    realmain(my_argc, my_argv);

    DEVTRACE("svc_main exiting\n");
    fflush(stdout);

    sm_svc_status.dwCurrentState = SERVICE_STOPPED;
    sm_svc_status.dwWin32ExitCode = NO_ERROR;
    SetServiceStatus(sm_svc_status_handle, &sm_svc_status);
}

int __cdecl wmain(int argc, wchar_t** argv)
{
    int err = NO_ERROR;
    if (argc == 2 && !wcscmp(argv[1], L"-delsvc")) {
        err = sm_del_svc();
    } else if (argc == 3 && !wcscmp(argv[1], L"-svc")) {
        err = sm_start_svc(argc, argv);
    } else if (argc == 3 && !wcscmp(argv[1], L"-svclisten")) {
        SERVICE_TABLE_ENTRYW svctable[] = {{L"", svc_main}, {NULL, NULL}};
        if (!StartServiceCtrlDispatcherW(svctable)) {
            err = GetLastError();
            if (err == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) {
                printf("Don't pass -svclisten from command line!\n");
            }
        }
    } else {
        err = realmain(argc, argv);
    }
    return err;
}
