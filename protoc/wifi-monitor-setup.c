#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <libnl3/netlink/netlink.h>
#include <libnl3/netlink/genl/genl.h>
#include <libnl3/netlink/genl/ctrl.h>
#include <linux/nl80211.h>

#define MONITOR_IF_NAME "mon0"
#define FREQ_2412 2412  // Channel 1 2.4GHz

struct nl80211_state {
    struct nl_sock *nl_sock;
    int nl80211_id;
};

// Forward declarations
static int error_handler(struct sockaddr_nl *nla, struct nlmsgerr *err, void *arg);
static int finish_handler(struct nl_msg *msg, void *arg);
static int ack_handler(struct nl_msg *msg, void *arg);
static int interface_exists(const char *ifname);
static int delete_interface_sysfs(const char *ifname);
static int delete_interface(struct nl80211_state *state, const char *ifname);
static int create_monitor_interface(struct nl80211_state *state, const char *phy_name, const char *if_name);
static int set_interface_up(const char *if_name);
static int set_interface_frequency(struct nl80211_state *state, const char *if_name, int freq);

// Error handling callbacks
static int error_handler(struct sockaddr_nl *nla, struct nlmsgerr *err, void *arg) {
    int *ret = arg;
    *ret = err->error;
    fprintf(stderr, "ERROR: nl80211 error %d: %s\n", err->error, strerror(-err->error));
    return NL_STOP;
}

static int finish_handler(struct nl_msg *msg, void *arg) {
    int *ret = arg;
    *ret = 0;
    return NL_SKIP;
}

static int ack_handler(struct nl_msg *msg, void *arg) {
    int *ret = arg;
    *ret = 0;
    return NL_STOP;
}

static int init_nl80211(struct nl80211_state *state) {
    state->nl_sock = nl_socket_alloc();
    if (!state->nl_sock) {
        fprintf(stderr, "Failed to allocate netlink socket.\n");
        return -1;
    }

    nl_socket_set_buffer_size(state->nl_sock, 8192, 8192);

    printf("DEBUG: Connecting to generic netlink\n");
    if (genl_connect(state->nl_sock)) {
        fprintf(stderr, "Failed to connect to generic netlink.\n");
        nl_socket_free(state->nl_sock);
        return -1;
    }

    printf("DEBUG: Resolving nl80211\n");
    state->nl80211_id = genl_ctrl_resolve(state->nl_sock, "nl80211");
    if (state->nl80211_id < 0) {
        fprintf(stderr, "nl80211 not found.\n");
        nl_socket_free(state->nl_sock);
        return -1;
    }

    return 0;
}

static void cleanup_nl80211(struct nl80211_state *state) {
    nl_socket_free(state->nl_sock);
}

static int interface_exists(const char *ifname) {
    struct ifreq ifr;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ-1);
    
    int ret = ioctl(sock, SIOCGIFFLAGS, &ifr);
    int exists = (ret >= 0);
    
    if (ret < 0 && errno != ENODEV) {
        perror("ioctl(SIOCGIFFLAGS)");
    }
    
    close(sock);
    return exists;
}

static int delete_interface_sysfs(const char *ifname) {
    char command[256];
    snprintf(command, sizeof(command), "ip link delete %s 2>/dev/null", ifname);
    return system(command);
}

static int delete_interface(struct nl80211_state *state, const char *ifname) {
    printf("DEBUG: Checking if interface %s exists...\n", ifname);
    
    int exists = interface_exists(ifname);
    if (exists < 0) {
        fprintf(stderr, "Error checking interface existence\n");
        return -1;
    }
    
    if (!exists) {
        printf("DEBUG: Interface %s does not exist, nothing to delete\n", ifname);
        return 0;
    }

    printf("DEBUG: Interface %s exists, attempting deletion\n", ifname);
    
    // Try sysfs method first
    if (delete_interface_sysfs(ifname) == 0) {
        printf("DEBUG: Successfully deleted interface using ip command\n");
        return 0;
    }

    struct nl_msg *msg = nlmsg_alloc();
    if (!msg) {
        fprintf(stderr, "Failed to allocate netlink message\n");
        return -1;
    }

    if (!genlmsg_put(msg, 0, 0, state->nl80211_id, 0, 0,
                NL80211_CMD_DEL_INTERFACE, 0)) {
        fprintf(stderr, "Failed to add generic netlink headers\n");
        nlmsg_free(msg);
        return -1;
    }

    int if_idx = if_nametoindex(ifname);
    if (if_idx == 0) {
        fprintf(stderr, "Failed to get interface index\n");
        nlmsg_free(msg);
        return -1;
    }

    if (nla_put_u32(msg, NL80211_ATTR_IFINDEX, if_idx) < 0) {
        fprintf(stderr, "Failed to add interface index to message\n");
        nlmsg_free(msg);
        return -1;
    }

    struct nl_cb *cb = nl_cb_alloc(NL_CB_DEFAULT);
    if (!cb) {
        fprintf(stderr, "Failed to allocate callbacks\n");
        nlmsg_free(msg);
        return -1;
    }

    int err = 1;
    nl_cb_err(cb, NL_CB_CUSTOM, error_handler, &err);
    nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler, &err);
    nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, ack_handler, &err);

    int ret = nl_send_auto_complete(state->nl_sock, msg);
    if (ret < 0) {
        fprintf(stderr, "Failed to send message: %s\n", nl_geterror(ret));
        nl_cb_put(cb);
        nlmsg_free(msg);
        return ret;
    }

    while (err > 0) {
        ret = nl_recvmsgs(state->nl_sock, cb);
        if (ret < 0) {
            fprintf(stderr, "Error receiving message: %s\n", nl_geterror(ret));
            break;
        }
    }

    nl_cb_put(cb);
    nlmsg_free(msg);
    return err;
}

static int create_monitor_interface(struct nl80211_state *state, const char *phy_name, const char *if_name) {
    struct nl_msg *msg = nlmsg_alloc();
    if (!msg) {
        fprintf(stderr, "Failed to allocate netlink message\n");
        return -1;
    }

    printf("DEBUG: Creating interface on %s with name %s\n", phy_name, if_name);
    
    if (interface_exists(if_name)) {
        printf("DEBUG: Interface exists, attempting to delete first\n");
        delete_interface_sysfs(if_name);
        usleep(100000);  // Give system time to remove interface
    }

    if (!genlmsg_put(msg, 0, 0, state->nl80211_id, 0, 0,
                NL80211_CMD_NEW_INTERFACE, 0)) {
        fprintf(stderr, "Failed to add generic netlink headers\n");
        nlmsg_free(msg);
        return -1;
    }
    
    int phy_idx;
    if (sscanf(phy_name, "phy%d", &phy_idx) != 1) {
        fprintf(stderr, "Failed to parse PHY index from %s\n", phy_name);
        nlmsg_free(msg);
        return -1;
    }
    printf("DEBUG: Using PHY index %d\n", phy_idx);
    
    if (nla_put_u32(msg, NL80211_ATTR_WIPHY, phy_idx) < 0 ||
        nla_put_string(msg, NL80211_ATTR_IFNAME, if_name) < 0 ||
        nla_put_u32(msg, NL80211_ATTR_IFTYPE, NL80211_IFTYPE_MONITOR) < 0) {
        fprintf(stderr, "Failed to add attributes to netlink message\n");
        nlmsg_free(msg);
        return -1;
    }

    struct nl_cb *cb = nl_cb_alloc(NL_CB_DEFAULT);
    if (!cb) {
        fprintf(stderr, "Failed to allocate callbacks\n");
        nlmsg_free(msg);
        return -1;
    }

    int err = 1;
    nl_cb_err(cb, NL_CB_CUSTOM, error_handler, &err);
    nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler, &err);
    nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, ack_handler, &err);

    int ret = nl_send_auto_complete(state->nl_sock, msg);
    if (ret < 0) {
        fprintf(stderr, "Failed to send message: %s\n", nl_geterror(ret));
        nl_cb_put(cb);
        nlmsg_free(msg);
        return ret;
    }

    while (err > 0) {
        ret = nl_recvmsgs(state->nl_sock, cb);
        if (ret < 0) {
            fprintf(stderr, "Error receiving message: %s\n", nl_geterror(ret));
            break;
        }
    }

    nl_cb_put(cb);
    nlmsg_free(msg);
    return err;
}

static int set_interface_up(const char *if_name) {
    struct ifreq ifr;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return -1;

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, if_name, IFNAMSIZ-1);

    // Get current flags
    if (ioctl(sock, SIOCGIFFLAGS, &ifr) < 0) {
        close(sock);
        return -1;
    }

    // Set UP flag
    ifr.ifr_flags |= IFF_UP;
    
    int err = ioctl(sock, SIOCSIFFLAGS, &ifr);
    close(sock);
    return err;
}

static int set_interface_frequency(struct nl80211_state *state, const char *if_name, int freq) {
    struct nl_msg *msg = nlmsg_alloc();
    if (!msg) return -1;

    if (!genlmsg_put(msg, 0, 0, state->nl80211_id, 0, 0,
                NL80211_CMD_SET_CHANNEL, 0)) {
        nlmsg_free(msg);
        return -1;
    }
    
    int if_idx = if_nametoindex(if_name);
    if (if_idx == 0) {
        nlmsg_free(msg);
        return -1;
    }

    if (nla_put_u32(msg, NL80211_ATTR_IFINDEX, if_idx) < 0 ||
        nla_put_u32(msg, NL80211_ATTR_WIPHY_FREQ, freq) < 0 ||
        nla_put_u32(msg, NL80211_ATTR_CHANNEL_WIDTH, NL80211_CHAN_WIDTH_20) < 0) {
        nlmsg_free(msg);
        return -1;
    }

    struct nl_cb *cb = nl_cb_alloc(NL_CB_DEFAULT);
    if (!cb) {
        nlmsg_free(msg);
        return -1;
    }

    int err = 1;
    nl_cb_err(cb, NL_CB_CUSTOM, error_handler, &err);
    nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler, &err);
    nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, ack_handler, &err);

    int ret = nl_send_auto_complete(state->nl_sock, msg);
    if (ret < 0) {
        nl_cb_put(cb);
        nlmsg_free(msg);
        return ret;
    }

    while (err > 0) {
        ret = nl_recvmsgs(state->nl_sock, cb);
        if (ret < 0) break;
    }

    nl_cb_put(cb);
    nlmsg_free(msg);
    return err;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <phy_name>\nExample: %s phy0\n", argv[0], argv[0]);
        return 1;
    }

    struct nl80211_state nlstate;
    if (init_nl80211(&nlstate) < 0) {
        fprintf(stderr, "Failed to initialize nl80211.\n");
        return 1;
    }

    printf("Cleaning up any existing monitor interface...\n");
    if (delete_interface(&nlstate, MONITOR_IF_NAME) < 0) {
        fprintf(stderr, "Warning: Failed to delete existing interface\n");
    }

    printf("Creating monitor interface %s...\n", MONITOR_IF_NAME);
    if (create_monitor_interface(&nlstate, argv[1], MONITOR_IF_NAME) < 0) {
        fprintf(stderr, "Failed to create monitor interface.\n");
        cleanup_nl80211(&nlstate);
        return 1;
    }

    usleep(100000);  // Wait for interface to be ready

    printf("Setting frequency to %d MHz...\n", FREQ_2412);
    if (set_interface_frequency(&nlstate, MONITOR_IF_NAME, FREQ_2412) < 0) {
        fprintf(stderr, "Failed to set frequency.\n");
	//cleanup_nl80211(&nlstate);
        //return 1;
    }

    printf("Bringing interface up...\n");
    if (set_interface_up(MONITOR_IF_NAME) < 0) {
        fprintf(stderr, "Failed to bring interface up.\n");
        cleanup_nl80211(&nlstate);
        return 1;
    }

    cleanup_nl80211(&nlstate);
    printf("Monitor mode setup complete on %s\n", MONITOR_IF_NAME);
    return 0;
}
