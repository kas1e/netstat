/* 
 * netstat - Network diagnostics and connection tracker for AmigaOS 4.
 * Objective: Provides a CLI utility to display TCP/UDP/ICMP connection statuses,
 *            interface metrics, routing tables, and protocol statistics via 
 *            bsdsocket.library, emulating Unix netstat's output and supporting 
 *            its core options (e.g., -a, -l, -n, -s, -i, -r) for cross-platform 
 *            compatibility and developer familiarity.

 * Roadshow-Specific Functions:
 *  - GetNetworkStatistics: Retrieves protocol stats (IP, TCP, UDP, ICMP) for detailed 
 *                          traffic analysis and debugging across all supported protocols.
 *  - ObtainInterfaceList/ReleaseInterfaceList: Enumerates network interfaces with 
 *                                              stats (MTU, packets, errors) for system 
 *                                              monitoring.
 *  - QueryInterfaceTags: Fetches per-interface properties (e.g., MTU, packet counts) 
 *                        to populate interface table.
 *  - socket/send/recv/CloseSocket: Manages routing socket for fetching and parsing 
 *                                 routing table entries.
 *  - Inet_NtoA/gethostbyaddr/getservbyport: Resolves IP addresses and ports to 
 *                                          human-readable names, toggleable with -n.
 * (с) 2025 kas1e.
 */
 
  
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <proto/exec.h>
#include <proto/dos.h>
#include <proto/bsdsocket.h>
#include <proto/socket.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/route.h>
#include <sys/sockio.h>
#include <netinet/in.h>
#include <netinet/tcp_fsm.h>
#include <netinet/ip_var.h>
#include <netinet/tcp_var.h>
#include <netinet/udp_var.h>
#include <netinet/icmp_var.h>
#include <netdb.h>


/* TCP state names based on <netinet/tcp_fsm.h> */
static const char *tcp_states[] = {
    "CLOSED",       /* TCPS_CLOSED */
    "LISTEN",       /* TCPS_LISTEN */
    "SYN_SENT",     /* TCPS_SYN_SENT */
    "SYN_RECEIVED", /* TCPS_SYN_RECEIVED */
    "ESTABLISHED",  /* TCPS_ESTABLISHED */
    "FIN_WAIT_1",   /* TCPS_FIN_WAIT_1 */
    "FIN_WAIT_2",   /* TCPS_FIN_WAIT_2 */
    "CLOSE_WAIT",   /* TCPS_CLOSE_WAIT */
    "CLOSING",      /* TCPS_CLOSING */
    "LAST_ACK",     /* TCPS_LAST_ACK */
    "TIME_WAIT"     /* TCPS_TIME_WAIT */
};

/* Interface stats structure */
struct InterfaceStats {
    char name[IFNAMSIZ]; /* Interface name, e.g., "eth0", "lo" */
    ULONG mtu;          /* MTU (e.g., 1500) */
    ULONG metric;       /* Routing metric */
    ULONG rx_packets;   /* RX-OK */
    ULONG rx_errors;    /* RX-ERR */
    ULONG rx_dropped;   /* RX-DRP */
    ULONG rx_overruns;  /* RX-OVR */
    ULONG tx_packets;   /* TX-OK */
    ULONG tx_errors;    /* TX-ERR */
    ULONG tx_dropped;   /* TX-DRP */
    ULONG tx_overruns;  /* TX-OVR */
    char flags[16];     /* Flags, e.g., "BMRU" */
};

/* Route entry structure */
struct RouteEntry {
    struct in_addr destination; /* Destination address, e.g., 0.0.0.0 */
    struct in_addr gateway;     /* Gateway address, e.g., 192.168.1.1 */
    struct in_addr genmask;     /* Netmask, e.g., 255.255.255.0 */
    char flags[16];             /* Flags, e.g., "UG" */
    ULONG refcnt;               /* Reference count */
    ULONG use;                  /* Packets sent */
    char iface[16];             /* Interface name, e.g., "eth0" */
};

/* Command-line options structure */
struct Options {
    int all;        /* -a, --all */
    int listening;  /* -l, --listening */
    int numeric;    /* -n, --numeric */
    int statistics; /* -s, --statistics */
    int interfaces; /* -i, --interfaces */
    int route;      /* -r, --route */
    int version;    /* --version */
    int help;       /* -h, --help */
    int invalid;    /* Flag for invalid options */
    char invalid_opt[32]; /* Store invalid option for error message */
};

/* Parse command-line arguments */
static void parse_args(int argc, char **argv, struct Options *opts) {
    for (int i = 1; i < argc; i++) {
        if (argv[i][0] == '-') {
            if (argv[i][1] == '-') { /* Long options */
                if (strcmp(argv[i], "--all") == 0) opts->all = 1;
                else if (strcmp(argv[i], "--listening") == 0) opts->listening = 1;
                else if (strcmp(argv[i], "--numeric") == 0) opts->numeric = 1;
                else if (strcmp(argv[i], "--statistics") == 0) opts->statistics = 1;
                else if (strcmp(argv[i], "--interfaces") == 0) opts->interfaces = 1;
                else if (strcmp(argv[i], "--route") == 0) opts->route = 1;
                else if (strcmp(argv[i], "--version") == 0) opts->version = 1;
                else if (strcmp(argv[i], "--help") == 0) opts->help = 1;
                else {
                    opts->invalid = 1;
                    strncpy(opts->invalid_opt, argv[i], sizeof(opts->invalid_opt) - 1);
                    opts->invalid_opt[sizeof(opts->invalid_opt) - 1] = '\0';
                }
            } else { /* Short options */
                for (int j = 1; argv[i][j]; j++) {
                    switch (argv[i][j]) {
                        case 'a': opts->all = 1; break;
                        case 'l': opts->listening = 1; break;
                        case 'n': opts->numeric = 1; break;
                        case 's': opts->statistics = 1; break;
                        case 'i': opts->interfaces = 1; break;
                        case 'r': opts->route = 1; break;
                        case 'h': opts->help = 1; break;
                        default:
                            opts->invalid = 1;
                            opts->invalid_opt[0] = argv[i][j];
                            opts->invalid_opt[1] = '\0';
                            break;
                    }
                    if (opts->invalid) break;
                }
            }
        } else {
            opts->invalid = 1;
            strncpy(opts->invalid_opt, argv[i], sizeof(opts->invalid_opt) - 1);
            opts->invalid_opt[sizeof(opts->invalid_opt) - 1] = '\0';
        }
        if (opts->invalid) break;
    }
}

/* Print per-protocol statistics */
static int print_statistics(struct SocketIFace *ISocket, int show_ip, int show_tcp, int show_udp, int show_icmp) {
    LONG result;

    if (show_ip) {
        struct ipstat ip_stats = {0};
        LONG size = ISocket->GetNetworkStatistics(NETSTATUS_ip, 1, NULL, 0);
        if (size < 0) {
            IDOS->Printf("Error: Failed to get IP stats buffer size: %d\n", ISocket->Errno());
            return RETURN_FAIL;
        }
        if (size >= sizeof(struct ipstat)) {
            result = ISocket->GetNetworkStatistics(NETSTATUS_ip, 1, &ip_stats, sizeof(struct ipstat));
            if (result == -1) {
                IDOS->Printf("Error: GetNetworkStatistics IP failed: %d\n", ISocket->Errno());
                return RETURN_FAIL;
            }
            IDOS->Printf("Ip:\n");
            IDOS->Printf("    %lu total packets received\n", ip_stats.ips_total);
            IDOS->Printf("    %lu packets forwarded\n", ip_stats.ips_forward);
            IDOS->Printf("    %lu incoming packets discarded\n", ip_stats.ips_odropped);
            IDOS->Printf("    %lu incoming packets delivered\n", ip_stats.ips_delivered);
            IDOS->Printf("    %lu packets sent\n", ip_stats.ips_localout);
        }
    }

    if (show_tcp) {
        struct tcpstat tcp_stats = {0};
        LONG size = ISocket->GetNetworkStatistics(NETSTATUS_tcp, 1, NULL, 0);
        if (size < 0) {
            IDOS->Printf("Error: Failed to get TCP stats buffer size: %d\n", ISocket->Errno());
            return RETURN_FAIL;
        }
        if (size >= sizeof(struct tcpstat)) {
            result = ISocket->GetNetworkStatistics(NETSTATUS_tcp, 1, &tcp_stats, sizeof(struct tcpstat));
            if (result == -1) {
                IDOS->Printf("Error: GetNetworkStatistics TCP failed: %d\n", ISocket->Errno());
                return RETURN_FAIL;
            }
            IDOS->Printf("Tcp:\n");
            IDOS->Printf("    %lu active connection openings\n", tcp_stats.tcps_connattempt);
            IDOS->Printf("    %lu passive connection openings\n", tcp_stats.tcps_accepts);
            IDOS->Printf("    %lu failed connection attempts\n", tcp_stats.tcps_drops);
            IDOS->Printf("    %lu connection resets received\n", tcp_stats.tcps_conndrops);
            IDOS->Printf("    %lu connections established\n", tcp_stats.tcps_connects);
            IDOS->Printf("    %lu segments received\n", tcp_stats.tcps_rcvpack);
            IDOS->Printf("    %lu segments sent out\n", tcp_stats.tcps_sndpack);
            IDOS->Printf("    %lu segments retransmitted\n", tcp_stats.tcps_sndrexmitpack);
        }
    }

    if (show_udp) {
        struct udpstat udp_stats = {0};
        LONG size = ISocket->GetNetworkStatistics(NETSTATUS_udp, 1, NULL, 0);
        if (size < 0) {
            IDOS->Printf("Error: Failed to get UDP stats buffer size: %d\n", ISocket->Errno());
            return RETURN_FAIL;
        }
        if (size >= sizeof(struct udpstat)) {
            result = ISocket->GetNetworkStatistics(NETSTATUS_udp, 1, &udp_stats, sizeof(struct udpstat));
            if (result == -1) {
                IDOS->Printf("Error: GetNetworkStatistics UDP failed: %d\n", ISocket->Errno());
                return RETURN_FAIL;
            }
            IDOS->Printf("Udp:\n");
            IDOS->Printf("    %lu packets received\n", udp_stats.udps_ipackets);
            IDOS->Printf("    %lu packets to unknown port received\n", udp_stats.udps_noport);
            IDOS->Printf("    %lu packet receive errors\n", udp_stats.udps_badsum + udp_stats.udps_badlen);
            IDOS->Printf("    %lu packets sent\n", udp_stats.udps_opackets);
        }
    }

    if (show_icmp) {
        struct icmpstat icmp_stats = {0};
        LONG size = ISocket->GetNetworkStatistics(NETSTATUS_icmp, 1, NULL, 0);
        if (size < 0) {
            IDOS->Printf("Error: Failed to get ICMP stats buffer size: %d\n", ISocket->Errno());
            return RETURN_FAIL;
        }
        if (size >= sizeof(struct icmpstat)) {
            result = ISocket->GetNetworkStatistics(NETSTATUS_icmp, 1, &icmp_stats, sizeof(struct icmpstat));
            if (result == -1) {
                IDOS->Printf("Error: GetNetworkStatistics ICMP failed: %d\n", ISocket->Errno());
                return RETURN_FAIL;
            }
            IDOS->Printf("Icmp:\n");
            IDOS->Printf("    %lu ICMP messages received\n", icmp_stats.icps_inhist[ICMP_ECHO] + icmp_stats.icps_inhist[ICMP_ECHOREPLY]);
            IDOS->Printf("    %lu input ICMP message failed\n", icmp_stats.icps_badcode + icmp_stats.icps_tooshort);
            IDOS->Printf("    %lu ICMP messages sent\n", icmp_stats.icps_outhist[ICMP_ECHO] + icmp_stats.icps_outhist[ICMP_ECHOREPLY]);
        }
    }

    return RETURN_OK;
}

/* Print interface statistics using Roadshow's ObtainInterfaceList */
static int print_interfaces(struct SocketIFace *ISocket) {
    struct List *interface_list = NULL;
    struct Node *node;
    int valid_ifaces = 0;

    IDOS->Printf("Kernel Interface table\n");
    IDOS->Printf("Iface  MTU Met  RX-OK RX-ERR RX-DRP RX-OVR  TX-OK TX-ERR TX-DRP TX-OVR Flg\n");

    /* Obtain the list of interfaces */
    interface_list = ISocket->ObtainInterfaceList();
    if (interface_list == NULL) {
        IDOS->Printf("Error: Cannot obtain interface list: %d\n", ISocket->Errno());
        return RETURN_OK;
    }

    /* Iterate through the interface list */
    for (node = interface_list->lh_Head; node->ln_Succ != NULL; node = node->ln_Succ) {
        struct InterfaceStats stats = {0};
        LONG mtu = 0, hardware_type = 0, state = 0;
        ULONG rx_packets = 0, tx_packets = 0, rx_errors = 0, tx_errors = 0, rx_dropped = 0, rx_overruns = 0, tx_overruns = 0;

        /* Skip if interface name is empty or too long */
        if (!node->ln_Name || strlen(node->ln_Name) >= IFNAMSIZ) {
            continue;
        }

        /* Copy interface name */
        strncpy(stats.name, node->ln_Name, sizeof(stats.name) - 1);
        stats.name[sizeof(stats.name) - 1] = '\0';

        /* Query interface information */
        if (ISocket->QueryInterfaceTags(node->ln_Name,
            IFQ_MTU, &mtu,
            IFQ_HardwareType, &hardware_type,
            IFQ_PacketsReceived, &rx_packets,
            IFQ_PacketsSent, &tx_packets,
            IFQ_BadData, &rx_errors,
            IFQ_Overruns, &rx_overruns,
            IFQ_UnknownTypes, &rx_dropped,
            IFQ_State, &state,
            TAG_DONE) != 0) {
            IDOS->Printf("Warning: QueryInterfaceTags failed for %s: %d\n", stats.name, ISocket->Errno());
            continue;
        }

        /* Fill statistics */
        stats.mtu = mtu;
        stats.metric = 0; /* Metric not provided, use 0 */
        stats.rx_packets = rx_packets;
        stats.rx_errors = rx_errors;
        stats.rx_dropped = rx_dropped;
        stats.rx_overruns = rx_overruns;
        stats.tx_packets = tx_packets;
        stats.tx_errors = rx_errors; /* IFQ_BadData does not separate RX/TX, use for both */
        stats.tx_dropped = 0; /* Not provided, use 0 */
        stats.tx_overruns = rx_overruns; /* IFQ_Overruns does not separate RX/TX, use for both */

        /* Build flags */
        char *f = stats.flags;
        if (state == SM_Up) *f++ = 'U';
        if (hardware_type == 1) *f++ = 'L'; /* ARPHRD_LOOPBACK = 1 */
        if (hardware_type == 6) *f++ = 'B'; /* ARPHRD_ETHER = 6, assume broadcast */
        *f++ = 'M'; /* Assume multicast for all interfaces */
        if (state == SM_Up) *f++ = 'R'; /* Running if Up */
        *f = '\0';

        /* Print interface stats */
        IDOS->Printf("%-6s %4lu %3lu %5lu %6lu %6lu %6lu %6lu %6lu %6lu %6lu %-5s\n",
                     stats.name, stats.mtu, stats.metric,
                     stats.rx_packets, stats.rx_errors, stats.rx_dropped, stats.rx_overruns,
                     stats.tx_packets, stats.tx_errors, stats.tx_dropped, stats.tx_overruns,
                     stats.flags);
        valid_ifaces++;
    }

    if (valid_ifaces == 0) {
        IDOS->Printf("No valid interfaces found\n");
    }

    /* Release the interface list */
    ISocket->ReleaseInterfaceList(interface_list);
    return RETURN_OK;
}

/* Print routing table */
static int print_routes(struct SocketIFace *ISocket) {
    IDOS->Printf("Kernel IP routing table\n");
    IDOS->Printf("Destination     Gateway         Genmask         Flags Refcnt Use Iface\n");

    /* Create a routing socket */
    int sock = ISocket->socket(AF_ROUTE, SOCK_RAW, 0);
    if (sock < 0) {
        IDOS->Printf("Error: Routing socket not supported: %d\n", ISocket->Errno());
        return RETURN_OK;
    }

    struct rt_msghdr rtm = {0};
    struct sockaddr_in dst = {0}, gateway = {0}, netmask = {0};
    char msg[512];
    int seq = 1;

    /* Prepare RTM_GET message */
    rtm.rtm_msglen = sizeof(struct rt_msghdr) + 3 * sizeof(struct sockaddr_in);
    rtm.rtm_version = RTM_VERSION;
    rtm.rtm_type = RTM_GET;
    rtm.rtm_addrs = RTA_DST | RTA_GATEWAY | RTA_NETMASK;
    rtm.rtm_pid = 0; /* No PID in AmigaOS */
    rtm.rtm_seq = seq++;

    dst.sin_family = AF_INET;
    gateway.sin_family = AF_INET;
    netmask.sin_family = AF_INET;

    memcpy(msg, &rtm, sizeof(rtm));
    memcpy(msg + sizeof(rtm), &dst, sizeof(dst));
    memcpy(msg + sizeof(rtm) + sizeof(dst), &gateway, sizeof(gateway));
    memcpy(msg + sizeof(rtm) + 2 * sizeof(dst), &netmask, sizeof(netmask));

    /* Send RTM_GET request */
    if (ISocket->send(sock, msg, rtm.rtm_msglen, 0) < 0) {
        IDOS->Printf("Error: Sending RTM_GET failed: %d\n", ISocket->Errno());
        ISocket->CloseSocket(sock);
        return RETURN_OK;
    }

    /* Receive response */
    char buf[1024];
    int len = ISocket->recv(sock, buf, sizeof(buf), 0);
    if (len < 0) {
        IDOS->Printf("Error: Receiving RTM_GET response failed: %d\n", ISocket->Errno());
        ISocket->CloseSocket(sock);
        return RETURN_OK;
    }

    struct rt_msghdr *rtm_resp = (struct rt_msghdr *)buf;
    if (rtm_resp->rtm_type != RTM_GET || rtm_resp->rtm_seq != rtm.rtm_seq) {
        IDOS->Printf("Error: Invalid RTM_GET response\n");
        ISocket->CloseSocket(sock);
        return RETURN_OK;
    }

    /* Parse response */
    struct sockaddr *sa = (struct sockaddr *)(rtm_resp + 1);
    struct RouteEntry route = {0};
    for (int i = 0; i < RTAX_MAX; i++) {
        if (rtm_resp->rtm_addrs & (1 << i)) {
            /* Use numeric indices since RTAX_* may not be defined in Roadshow */
            if (i == 0) { /* RTAX_DST */
                route.destination = ((struct sockaddr_in *)sa)->sin_addr;
            } else if (i == 1) { /* RTAX_GATEWAY */
                route.gateway = ((struct sockaddr_in *)sa)->sin_addr;
            } else if (i == 2) { /* RTAX_NETMASK */
                route.genmask = ((struct sockaddr_in *)sa)->sin_addr;
            }
            sa = (struct sockaddr *)((char *)sa + sizeof(struct sockaddr));
        }
    }

    route.refcnt = 0; /* No rtm_refcnt in rt_msghdr */
    route.use = rtm_resp->rtm_use;
    strncpy(route.iface, "unknown", sizeof(route.iface) - 1);
    char *f = route.flags;
    if (rtm_resp->rtm_flags & RTF_UP) *f++ = 'U';
    if (rtm_resp->rtm_flags & RTF_GATEWAY) *f++ = 'G';
    if (rtm_resp->rtm_flags & RTF_HOST) *f++ = 'H';
    *f = '\0';

    /* Format and print route */
    char dst_str[16], gw_str[16], mask_str[16];
    const char *dst_ptr = ISocket->Inet_NtoA(route.destination.s_addr);
    strncpy(dst_str, dst_ptr ? dst_ptr : "0.0.0.0", sizeof(dst_str) - 1);
    dst_str[sizeof(dst_str) - 1] = '\0';
    const char *gw_ptr = ISocket->Inet_NtoA(route.gateway.s_addr);
    strncpy(gw_str, gw_ptr ? gw_ptr : "0.0.0.0", sizeof(gw_str) - 1);
    gw_str[sizeof(gw_str) - 1] = '\0';
    const char *mask_ptr = ISocket->Inet_NtoA(route.genmask.s_addr);
    strncpy(mask_str, mask_ptr ? mask_ptr : "0.0.0.0", sizeof(mask_str) - 1);
    mask_str[sizeof(mask_str) - 1] = '\0';

    IDOS->Printf("%-15s %-15s %-15s %-5s %6lu %3lu %-6s\n",
                 dst_str, gw_str, mask_str, route.flags,
                 route.refcnt, route.use, route.iface);

    ISocket->CloseSocket(sock);
    return RETURN_OK;
}

/* Print connections for TCP or UDP */
static int print_connections(struct SocketIFace *ISocket, LONG type, int is_udp, 
                            int show_all, int listening_only, int numeric) {
    struct protocol_connection_data *conns = NULL;

    /* Get buffer size for connections */
    LONG size = ISocket->GetNetworkStatistics(type, NETWORKSTATUS_VERSION, NULL, 0);
    if (size < 0) {
        IDOS->Printf("Error: Failed to get buffer size for %s: %d\n", is_udp ? "UDP" : "TCP", ISocket->Errno());
        return RETURN_FAIL;
    }
    if (size == 0) {
        return RETURN_OK;
    }

    /* Allocate memory for connections */
    conns = IExec->AllocVecTags(size, 
        AVT_Type, MEMF_SHARED,
        AVT_ClearWithValue, 0,
        TAG_DONE);
    if (!conns) {
        IDOS->Printf("Error: Memory allocation failed\n");
        return RETURN_FAIL;
    }

    /* Get connection data */
    LONG result = ISocket->GetNetworkStatistics(type, NETWORKSTATUS_VERSION, conns, size);
    if (result == -1) {
        IDOS->Printf("Error: GetNetworkStatistics failed for %s: %d\n", is_udp ? "UDP" : "TCP", ISocket->Errno());
        IExec->FreeVec(conns);
        return RETURN_FAIL;
    }
    if (result <= 0) {
        IExec->FreeVec(conns);
        return RETURN_OK;
    }

    int num_conns = result / sizeof(struct protocol_connection_data);
    if (num_conns <= 0) {
        IExec->FreeVec(conns);
        return RETURN_OK;
    }

    /* Iterate through connections */
    for (int i = 0; i < num_conns; i++) {
        if (!is_udp && (conns[i].pcd_tcp_state < 0 || conns[i].pcd_tcp_state >= 11)) {
            continue;
        }

        if (listening_only && conns[i].pcd_tcp_state != TCPS_LISTEN) {
            continue;
        }
        if (!show_all && !listening_only && conns[i].pcd_tcp_state == TCPS_LISTEN) {
            continue;
        }

        char local_addr[64], foreign_addr[64];
        char port_buf[32];

        /* Format local address */
        const char *ip_str = ISocket->Inet_NtoA(conns[i].pcd_local_address.s_addr);
        if (!ip_str) ip_str = "0.0.0.0";
        const char *local_name = ip_str;
        if (!numeric) {
            struct hostent *h = ISocket->gethostbyaddr((char *)&conns[i].pcd_local_address, 
                                                       sizeof(struct in_addr), AF_INET);
            if (h && h->h_name && h->h_name[0]) {
                local_name = h->h_name;
            }
        }
        if (numeric) {
            snprintf(port_buf, sizeof(port_buf), "%d", conns[i].pcd_local_port);
        } else {
            struct servent *s = ISocket->getservbyport(conns[i].pcd_local_port, 
                                                       is_udp ? "udp" : "tcp");
            if (s && s->s_name && s->s_name[0]) {
                snprintf(port_buf, sizeof(port_buf), "%s", s->s_name);
            } else {
                snprintf(port_buf, sizeof(port_buf), "%d", conns[i].pcd_local_port);
            }
        }
        snprintf(local_addr, sizeof(local_addr), "%s:%s", local_name, port_buf);

        /* Format foreign address */
        const char *foreign_ip_str = ISocket->Inet_NtoA(conns[i].pcd_foreign_address.s_addr);
        if (!foreign_ip_str) foreign_ip_str = "0.0.0.0";
        const char *foreign_name = foreign_ip_str;
        if (!numeric && conns[i].pcd_tcp_state != TCPS_LISTEN) {
            struct hostent *h = ISocket->gethostbyaddr((char *)&conns[i].pcd_foreign_address, 
                                                       sizeof(struct in_addr), AF_INET);
            if (h && h->h_name && h->h_name[0]) {
                foreign_name = h->h_name;
            }
        }
        if (conns[i].pcd_tcp_state == TCPS_LISTEN) {
            snprintf(port_buf, sizeof(port_buf), "*");
        } else if (numeric) {
            snprintf(port_buf, sizeof(port_buf), "%d", conns[i].pcd_foreign_port);
        } else {
            struct servent *s = ISocket->getservbyport(conns[i].pcd_foreign_port, 
                                                       is_udp ? "udp" : "tcp");
            if (s && s->s_name && s->s_name[0]) {
                snprintf(port_buf, sizeof(port_buf), "%s", s->s_name);
            } else {
                snprintf(port_buf, sizeof(port_buf), "%d", conns[i].pcd_foreign_port);
            }
        }
        snprintf(foreign_addr, sizeof(foreign_addr), "%s:%s", foreign_name, port_buf);

        /* Determine connection state */
        const char *state_str = is_udp ? "-" : 
                                (conns[i].pcd_tcp_state >= 0 && conns[i].pcd_tcp_state < 11 ? 
                                 tcp_states[conns[i].pcd_tcp_state] : "UNKNOWN");

        /* Print connection */
        IDOS->Printf("%-5s %6lu %6lu %-23.23s %-23.23s %-12.12s\n",
                     is_udp ? "udp" : "tcp",
                     conns[i].pcd_receive_queue_size,
                     conns[i].pcd_send_queue_size,
                     local_addr,
                     foreign_addr,
                     state_str);
    }

    IExec->FreeVec(conns);
    return RETURN_OK;
}

int main(int argc, char **argv) {
    struct SocketIFace *ISocket = NULL;
    struct Library *SocketBase = NULL;
    struct Options opts = {0};
    LONG result = RETURN_FAIL;

    /* Parse command-line arguments */
    parse_args(argc, argv, &opts);

    if (opts.invalid) {
        IDOS->Printf("netstat: invalid option -- '%s'\n", opts.invalid_opt);
        IDOS->Printf("Try 'netstat --help' for more information.\n");
        return RETURN_FAIL;
    }

    if (opts.help) {
        IDOS->Printf(
            "Usage: netstat [options]\n"
            "Options:\n"
            "  -a, --all            Show all sockets (listening and non-listening)\n"
            "  -l, --listening      Show only listening sockets\n"
            "  -n, --numeric        Show numerical addresses and ports\n"
            "  -s, --statistics     Show network statistics\n"
            "  -i, --interfaces     Display interface table\n"
            "  -r, --route          Show routing table\n"
            "  --version            Show version\n"
            "  -h, --help           Show this help\n"
            "Default: Show TCP and UDP connections with resolved names\n");
        return RETURN_OK;
    }

    if (opts.version) {
        IDOS->Printf("netstat for AmigaOS 4, version 1.1\n");
        return RETURN_OK;
    }

    /* Open bsdsocket.library */
    SocketBase = IExec->OpenLibrary("bsdsocket.library", 4);
    if (!SocketBase) {
        IDOS->Printf("Error: Cannot open bsdsocket.library\n");
        return RETURN_FAIL;
    }

    /* Get socket interface */
    ISocket = (struct SocketIFace *)IExec->GetInterface(SocketBase, "main", 1, NULL);
    if (!ISocket) {
        IDOS->Printf("Error: Cannot get ISocket interface\n");
        IExec->CloseLibrary(SocketBase);
        return RETURN_FAIL;
    }

    /* Check if GetNetworkStatistics is supported */
    LONG supported = FALSE;
    if (ISocket->SocketBaseTags(SBTM_GETREF(SBTC_HAVE_STATUS_API), &supported, TAG_END) != 0) {
        supported = FALSE;
    }
    if (!supported && opts.statistics) {
        IDOS->Printf("Error: GetNetworkStatistics not supported\n");
        IExec->DropInterface((struct Interface *)ISocket);
        IExec->CloseLibrary(SocketBase);
        return RETURN_FAIL;
    }

    /* Default behavior: show all connections */
    if (argc == 1 || (opts.numeric && !opts.all && !opts.listening && !opts.statistics && !opts.interfaces && !opts.route)) {
        opts.all = 1;
    }

    /* Show connections if -a, -l, or -n is specified and no other display options */
    if ((opts.all || opts.listening || opts.numeric) && !opts.statistics && !opts.interfaces && !opts.route) {
        IDOS->Printf("Active Internet connections (%s)\n",
                     opts.listening && !opts.all ? "only servers" : 
                     opts.all ? "servers and established" : "w/o servers");
        IDOS->Printf("Proto Recv-Q Send-Q Local Address           Foreign Address         State\n");

        /* Show TCP connections */
        result = print_connections(ISocket, NETSTATUS_tcp_sockets, 0, opts.all, opts.listening, opts.numeric);
        if (result != RETURN_OK) goto cleanup;

        /* Show UDP connections */
        result = print_connections(ISocket, NETSTATUS_udp_sockets, 1, opts.all, opts.listening, opts.numeric);
        if (result != RETURN_OK) goto cleanup;
    }

    /* Show interface table */
    if (opts.interfaces && !opts.statistics) {
        result = print_interfaces(ISocket);
        if (result != RETURN_OK) goto cleanup;
    }

    /* Show routing table */
    if (opts.route && !opts.statistics) {
        result = print_routes(ISocket);
        if (result != RETURN_OK) goto cleanup;
    }

    /* Show statistics */
    if (opts.statistics) {
        result = print_statistics(ISocket, 1, 1, 1, 1); /* Show all protocols */
        if (result != RETURN_OK) goto cleanup;
    }

    if (opts.all || opts.listening || opts.numeric || opts.route || opts.interfaces || opts.statistics) {
        result = RETURN_OK;
    }

cleanup:
    if (ISocket) IExec->DropInterface((struct Interface *)ISocket);
    if (SocketBase) IExec->CloseLibrary(SocketBase);
    return result;
}
