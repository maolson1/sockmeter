// Sockmeter: a Windows network performance measurement tool.
// Currently only supports TCP.
//
// Compared to iperf: Optimized for Windows with IOCP.
//
// Compared to ntttcp: Allows the thread count and socket count to be
// separately configured; no need to re-run the service on each execution;
// the service uses a single port number.
//
// TODO: avg packet size
// TODO: cpu%
// TODO: latency
// TODO: write stats to json
// TODO: TCP_NODELAY option
// TODO: service sends back info (cpu% etc)
// TODO: consider SO_LINGER/SO_DONTLINGER
// TODO: UDP
// TODO: Should -nbytes be per-socket or across all sockets?
// TODO: Currently the service side thread count is min(64, numProc).
//       Consider creating a number of threads equal to the number of
//       RSS processors and assigning flows to threads based on the output of
//       SIO_QUERY_RSS_PROCESSOR_INFO rather than round-robin.
// TODO: Less alarming messages for ungraceful connection closure on service
//       side (or perhaps do graceful connection closure).

#define WIN32_LEAN_AND_MEAN 1
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>
#include <winsock2.h>
#include <mswsock.h>
#include <ws2tcpip.h>
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
"   -send [h] [p]: Send to host h at port p. Pass multiple times to\n" \
"                  send data to multiple peers.\n" \
"   -recv [h] [p]: receive from host h at port p. Pass multiple times to\n" \
"                  receive data from multiple peers.\n" \
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
    SmDirectionRecv
} SM_DIRECTION;

#pragma pack(push,1)
typedef struct {
    SM_DIRECTION dir;
    ULONG64 to_xfer;
} SM_MSG_HELLO;
#pragma pack(pop)

typedef struct _SM_PEER {
    struct _SM_PEER* next;
    wchar_t host[NI_MAXHOST];
    wchar_t port[NI_MAXSERV];
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

typedef struct _SM_FLOW {
    struct _SM_FLOW* next;
    SOCKET sock;
    SM_IO* io;
    SM_DIRECTION dir;
    ULONG64 xferred;
    ULONG64 to_xfer; // 0 means send indefinitely.
} SM_FLOW;

typedef struct _SM_THREAD {
    struct _SM_THREAD* next;
    HANDLE t;
    HANDLE iocp;
    HANDLE mutex;
    ULONG64 xferred_tx; // sum of bytes tx'd by deleted flows.
    ULONG64 xferred_rx; // sum of bytes rx'd by deleted flows.
    SM_FLOW* flows;
    ULONG numflows;
} SM_THREAD;

// Variables for client and service:
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
ULONG64 sm_perf_freq; // ticks/sec

// Variables for service only:
SOCKADDR_INET sm_svcaddr;
size_t sm_svcaddrlen;

ULONG64 sm_curtime_ms(void)
{
    ULONG64 ticks = 0;
    if (!QueryPerformanceCounter((LARGE_INTEGER*)&ticks)) {
        printf("QueryPerformanceCounter failed with %d\n", GetLastError());
        return 0;
    }
    return ticks * 1000 / sm_perf_freq;
}

SM_PEER* sm_new_peer(wchar_t* host, wchar_t* port, SM_DIRECTION dir)
{
    size_t hostlen = wcslen(host);
    if (hostlen > NI_MAXHOST) {
        printf("Input hostname too long\n");
        return NULL;
    }

    size_t portlen = wcslen(port);
    if (portlen > NI_MAXSERV) {
        printf("Input port string too long\n");
        return NULL;
    }

    SM_PEER* peer = malloc(sizeof(SM_PEER));
    if (peer == NULL) {
        printf("Failed to allocate SM_PEER\n");
        return NULL;
    }

    wcsncpy_s(peer->host, NI_MAXHOST * sizeof(wchar_t), host, hostlen);
    wcsncpy_s(peer->port, NI_MAXSERV * sizeof(wchar_t), port, portlen);
    peer->dir = dir;

    peer->next = sm_peers;
    sm_peers = peer;

    return peer;
}

void sm_del_peer(SM_PEER* peer)
{
    free(peer);
}

SM_IO* sm_new_io(SM_DIRECTION dir)
{
    SM_IO* io = malloc(sizeof(SM_IO));
    if (io == NULL) {
        printf("Failed to allocate SM_IO\n");
        return NULL;
    }
    memset(io, 0, sizeof(*io));
    io->ov.hEvent = WSACreateEvent();
    if (io->ov.hEvent == WSA_INVALID_EVENT) {
        printf("WSACreateEvent failed with %d\n", WSAGetLastError());
        free(io);
        return NULL;
    }
    io->dir = dir;
    io->xferred = 0;
    io->bufsize = sm_iosize;
    io->buf = malloc(io->bufsize);
    if (io->buf == NULL) {
        printf("failed to allocate IO buffer of size %d\n", io->bufsize);
        WSACloseEvent(io->ov.hEvent);
        free(io);
        return NULL;
    }
    io->to_xfer = io->bufsize;
    io->wsabuf.buf = io->buf;
    io->wsabuf.len = io->to_xfer;
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

SM_FLOW* sm_new_flow(
    SM_THREAD* thread, SOCKET sock, SM_DIRECTION dir, ULONG64 to_xfer)
{
    SM_FLOW* flow = malloc(sizeof(SM_FLOW));
    if (flow == NULL) {
        printf("Failed to allocate SM_FLOW\n");
        return NULL;
    }
    memset(flow, 0, sizeof(*flow));
    flow->sock = sock;
    if (CreateIoCompletionPort(
            (HANDLE)flow->sock, thread->iocp, (ULONG_PTR)flow, 0) == NULL) {
        printf("Associating sock to iocp failed with %d\n", GetLastError());
        free(flow);
        return NULL;
    }
    flow->io = sm_new_io(dir);
    if (flow->io == NULL) {
        free(flow);
        return NULL;
    }
    flow->dir = dir;
    flow->xferred = 0;
    flow->to_xfer = to_xfer;

    WaitForSingleObject(thread->mutex, INFINITE);
    flow->next = thread->flows;
    thread->flows = flow;
    thread->numflows++;
    ReleaseMutex(thread->mutex);

    return flow;
}

void sm_del_flow(SM_THREAD* thread, SM_FLOW* flow)
{
    WaitForSingleObject(thread->mutex, INFINITE);
    SM_FLOW** f = &(thread->flows);
    while (*f != flow) {
        f = &((*f)->next);
    }
    *f = flow->next;
    thread->numflows--;
    if (flow->dir == SmDirectionSend) {
        thread->xferred_tx += flow->xferred;
    } else {
        thread->xferred_rx += flow->xferred;
    }
    ReleaseMutex(thread->mutex);

    if (flow->sock != INVALID_SOCKET) {
        closesocket(flow->sock);
    }

    if (flow->io != NULL) {
        sm_del_io(flow->io);
    }

    free(flow);
}

SM_THREAD* sm_new_thread(LPTHREAD_START_ROUTINE fn)
{
    SM_THREAD* thread = malloc(sizeof(SM_THREAD));
    if (thread == NULL) {
        printf("Failed to allocate SM_THREAD\n");
        return NULL;
    }
    memset(thread, 0, sizeof(*thread));

    thread->iocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
    if (thread->iocp == NULL) {
        printf("CreateIoCompletionPort failed with %d\n", GetLastError());
        free(thread);
        return NULL;
    }
    thread->numflows = 0;
    thread->flows = NULL;

    thread->mutex = CreateMutex(NULL, FALSE, NULL);
    if (thread->mutex == NULL) {
        printf("CreateMutex failed with %d\n", GetLastError());
        CloseHandle(thread->iocp);
        free(thread);
        return NULL;
    }

    thread->t = CreateThread(NULL, 0, fn, (void*)thread, 0, NULL);
    if (thread->t == NULL) {
        printf("CreateThread failed with %d\n", GetLastError());
        CloseHandle(thread->mutex);
        CloseHandle(thread->iocp);
        free(thread);
        return NULL;
    }

    thread->next = sm_threads;
    sm_threads = thread;
    return thread;
}

void sm_del_thread(SM_THREAD* thread)
{
    // This is called from the main thread on termination, and we assume
    // the SM_THREAD's thread is already terminated.

    // Normally flows are deleted as they finish, but in error conditions
    // we may terminate early and still have some flows to delete here.
    while (thread->flows != NULL) {
        sm_del_flow(thread, thread->flows);
    }

    CloseHandle(thread->t);
    CloseHandle(thread->iocp);
    CloseHandle(thread->mutex);
    free(thread);
}

int sm_start_flow(SM_FLOW* flow)
{
    // Post the flow's initial IO. The IO will be subsequently reposted
    // by sm_io_loop.

    int err = 0;
    if (flow->dir == SmDirectionSend) {
        err = WSASend(
                flow->sock, &(flow->io->wsabuf), 1, NULL,
                0, &(flow->io->ov), NULL);
    } else {
        err = WSARecv(
                flow->sock, &(flow->io->wsabuf), 1, NULL,
                &(flow->io->recvflags), &(flow->io->ov), NULL);
    }
    if (err == SOCKET_ERROR) {
        err = WSAGetLastError();
        if (err != WSA_IO_PENDING) {
            if (flow->dir == SmDirectionSend) {
                printf("WSASend failed with %d\n", err);
            } else {
                printf("WSARecv failed with %d\n", err);
            }
        } else {
            err = 0;
        }
    }
    return err;
}

int sm_io_loop(SM_THREAD* thread, ULONG timeout_ms)
{
    // Loop on GetQueuedCompletionStatus, reposting IOs or shutting down
    // flows as appropriate.

    int err = 0;
    int xferred;
    SM_FLOW* flow;
    SM_IO* io;

    while (TRUE) {

        if (!GetQueuedCompletionStatus(
                thread->iocp, (DWORD*)&xferred, (ULONG_PTR*)&flow,
                (LPOVERLAPPED*)&io, timeout_ms)) {
            err = GetLastError();
            printf("GetQueuedCompletionStatus failed with %d\n", err);
            break;
        }

        if (sm_cleanup_time || xferred == 0) {
            break;
        }

        // Figure out how much to transfer next and adjust the wsabuf
        // appropriately: Either we want to transfer the remainder of the IO, or
        // we want to resend the IO from the beginning, or we are near the end
        // of the stream and want to send only part of the IO.

        // Reminder: (flow->to_xfer == 0) means send forever.

        io->xferred += xferred;
        if (io->xferred < io->to_xfer) {
            io->wsabuf.buf = &(io->buf[io->xferred]);
            io->wsabuf.len = io->to_xfer - io->xferred;
        } else if (flow->to_xfer == 0 ||
                   flow->to_xfer > flow->xferred + io->to_xfer) {
            flow->xferred += io->to_xfer;
            if (flow->to_xfer != 0 &&
                io->to_xfer > (flow->to_xfer - flow->xferred)) {
                io->to_xfer = (DWORD)(flow->to_xfer - flow->xferred);
            }
            io->wsabuf.buf = io->buf;
            io->wsabuf.len = io->to_xfer;
            io->xferred = 0;
        } else {
            flow->xferred = flow->to_xfer;
        }

        if (flow->to_xfer == 0 || flow->xferred < flow->to_xfer) {
            if (io->dir == SmDirectionSend) {
                err = WSASend(
                    flow->sock, &(io->wsabuf), 1, NULL,
                    0, &(io->ov), NULL);
            } else {
                err = WSARecv(
                    flow->sock, &(flow->io->wsabuf), 1, NULL,
                    &(flow->io->recvflags), &(flow->io->ov), NULL);
            }
            if (err == SOCKET_ERROR) {
                err = WSAGetLastError();
                if (err != WSA_IO_PENDING) {
                    if (io->dir == SmDirectionSend) {
                        printf("WSASend failed with %d\n", err);
                    } else {
                        printf("WSARecv failed with %d\n", err);
                    }
                    break;
                } else {
                    err = 0;
                }
            }
        } else {
            shutdown(flow->sock, SD_BOTH);
            sm_del_flow(thread, flow);
            if (thread->numflows == 0) {
                break;
            }
        }
    }

    return err;
}

int sm_connect_flow(SM_THREAD* thread, SM_PEER* peer)
{
    // Create an outbound connection and an SM_FLOW for it.

    int err = 0;
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

    SM_FLOW* flow =
        sm_new_flow(thread, sock, peer->dir, sm_nbytes / sm_nsock);
    if (flow == NULL) {
        err = 1;
        goto exit;
    }

    SOCKADDR_INET laddr = {0};
    DWORD laddrlen = sizeof(laddr);
    SOCKADDR_INET raddr = {0};
    DWORD raddrlen = sizeof(raddr);
    if (!WSAConnectByNameW(
            flow->sock, peer->host, peer->port, &laddrlen, (SOCKADDR*)&laddr,
            &raddrlen, (SOCKADDR*)&raddr, NULL, NULL)) {
        err = WSAGetLastError();
        printf("WSAConnectByNameW failed with %d\n", err);
        goto exit;
    }
    if (setsockopt(flow->sock, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, NULL, 0)
            == SOCKET_ERROR) {
        err = WSAGetLastError();
        printf("setsockopt(SO_UPDATE_CONNECT_CONTEXT) failed with %d\n", err);
        goto exit;
    }

    SM_MSG_HELLO hello = {0};
    // If we send then the service receives, and vice versa.
    hello.dir =
        (flow->dir == SmDirectionSend) ? SmDirectionRecv : SmDirectionSend;
    hello.to_xfer = flow->to_xfer;
    int bytes_sent = send(flow->sock, (char*)&hello, sizeof(hello), 0);
    if (bytes_sent == SOCKET_ERROR) {
        err = WSAGetLastError();
        printf("send (hello) failed with %d\n", err);
        goto exit;
    } else if (bytes_sent != sizeof(hello)) {
        printf("send unexpectedly sent only part of HELLO\n");
        err = 1;
        goto exit;
    }
exit:
    if (err != 0) {
        if (sock != INVALID_SOCKET) {
            closesocket(sock);
        }
    }
    return err;
}

SM_FLOW* sm_accept_flow(SOCKET ls, SM_THREAD* thread)
{
    // Call accept on the input listening socket, and create an SM_FLOW for
    // the resulting inbound connection.

    SOCKET ss = accept(ls, NULL, NULL);
    if (ss == INVALID_SOCKET) {
        printf("Accept failed with %d\n", WSAGetLastError());
        return NULL;
    }

    DEVTRACE("Accepted connection\n");

    SM_MSG_HELLO hello = {0};
    int xferred = recv(ss, (char*)&hello, sizeof(hello), MSG_WAITALL);
    if (xferred == SOCKET_ERROR) {
        printf("recv(hello) failed with %d\n", WSAGetLastError());
        closesocket(ss);
        return NULL;
    }

    SM_FLOW* flow = sm_new_flow(thread, ss, hello.dir, hello.to_xfer);
    if (flow == NULL) {
        printf("Failed to create new flow for accept socket\n");
        closesocket(ss);
    }
    return flow;
}

DWORD sm_service_fn(void* param)
{
    while (TRUE) {
        sm_io_loop((SM_THREAD*)param, INFINITE);
    }
    return 0;
}

VOID sm_service(void)
{
    int err = 0;
    SOCKET ls = INVALID_SOCKET;
    SM_THREAD* thread;

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
        SM_FLOW* flow = sm_accept_flow(ls, thread);
        if (flow == NULL) {
            goto exit;
        }
        thread = thread->next;
        if (thread == NULL) {
            thread = sm_threads;
        }

        err = sm_start_flow(flow);
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

VOID sm_client(void)
{
    int err;
    SM_THREAD* thread;
    SM_PEER* peer;
    SM_FLOW* flow;

    for (int i = 0; i < sm_nthread; i++) {
        thread = sm_new_thread(sm_client_fn);
        if (thread == NULL) {
            return;
        }
    }

    printf("Connecting...\n");

    // Assign flows to threads and peers round-robin.
    //
    // We first connect all flows and then start all flows, rather than
    // starting each flow as it's connected. This is for two reasons:
    // 1) If we fail to connect to one of multiple peers, we will abort and
    //    it's better not to have started transferring data with the other
    //    peers.
    // 2) This makes synchronization in sm_io_loop easier- we add all the flows
    //    to the thread so that "numflows" is a complete count, and only then
    //    do we post the IOs, so we won't have a race where numflows drops
    //    back to zero before we've added all of the flows.

    thread = sm_threads;
    peer = sm_peers;
    for (int i = 0; i < sm_nsock; i++) {
        err = sm_connect_flow(thread, peer);
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

    // The datapath is optimized, but connection establishment is not:
    // we call WSAConnectByName serially, which means potentially a lot of
    // unnecessary name lookups and multiple syscalls to connect and send the
    // HELLO, which ConnectEx could do in a single syscall.
    //
    // Also, if some of the connections experienced dropped SYN segments, they
    // will see major delays due to the large retransmission period of SYNs.
    // if we included that delay in our rate calculation, it could cause
    // confusing noise.
    //
    // So, we don't start timing until the connections are all established.
    // Benchmarking "connections per second" as opposed to "bytes per second"
    // is future work.

    ULONG64 t_start_ms = sm_curtime_ms();

    thread = sm_threads;
    while (thread != NULL) {
        WaitForSingleObject(thread->mutex, INFINITE);
        flow = thread->flows;
        while (flow != NULL) {
            err = sm_start_flow(flow);
            if (err != 0) {
                ReleaseMutex(thread->mutex);
                return;
            }
            flow = flow->next;
        }
        ReleaseMutex(thread->mutex);
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
            // Depending on whether we're in -t or -nbytes mode, the flows
            // may or may not have been deleted at this point. So add the
            // thread's count of bytes xferred by deleted flows to the
            // counts in any active flows.
            WaitForSingleObject(thread->mutex, INFINITE);
            xferred_tx += thread->xferred_tx;
            xferred_rx += thread->xferred_rx;
            flow = thread->flows;
            while (flow != NULL) {
                if (flow->dir == SmDirectionSend) {
                    xferred_tx += flow->xferred;
                } else {
                    xferred_rx += flow->xferred;
                }
                flow = flow->next;
            }
            ReleaseMutex(thread->mutex);
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

    if (!QueryPerformanceFrequency((LARGE_INTEGER*)&sm_perf_freq)) {
        err = GetLastError();
        printf("QueryPerformanceFrequency failed with %d\n", err);
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
            if (svcmode) {
                err = ERROR_INVALID_PARAMETER;
                goto exit;
            }
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
        } else {
            printf(USAGE);
            err = ERROR_INVALID_PARAMETER;
            goto exit;
        }
    }

    if (svcmode && numpeers > 0) {
        printf("ERROR: cannot pass both -svc and (-send or -recv).\n");
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

    SM_THREAD* thread = sm_threads;
    while (thread != NULL) {
        SM_THREAD* next = thread->next;
        sm_del_thread(thread);
        thread = next;
    }

    SM_PEER* peer = sm_peers;
    while (peer != NULL) {
        SM_PEER* next = peer->next;
        sm_del_peer(peer);
        peer = next;
    }

    if (need_wsacleanup) {
        WSACleanup();
    }

    return err;
}
