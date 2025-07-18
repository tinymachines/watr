#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <libnl3/netlink/netlink.h>
#include <libnl3/netlink/genl/genl.h>
#include <libnl3/netlink/genl/ctrl.h>
#include <linux/nl80211.h>

struct nl80211_state {
    struct nl_sock *nl_sock;
    int nl80211_id;
};

static int error_handler(struct sockaddr_nl *nla, struct nlmsgerr *err, void *arg) {
    int *ret = arg;
    *ret = err->error;
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

static int check_monitor_capability(struct nl_msg *msg, void *arg) {
    struct nlattr *tb_msg[NL80211_ATTR_MAX + 1];
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    
    nla_parse(tb_msg, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
              genlmsg_attrlen(gnlh, 0), NULL);

    if (!tb_msg[NL80211_ATTR_WIPHY_NAME] || !tb_msg[NL80211_ATTR_SUPPORTED_IFTYPES])
        return NL_SKIP;

    const char *name = nla_get_string(tb_msg[NL80211_ATTR_WIPHY_NAME]);
    struct nlattr *tb_modes[NL80211_IFTYPE_MAX + 1];
    nla_parse(tb_modes, NL80211_IFTYPE_MAX,
              nla_data(tb_msg[NL80211_ATTR_SUPPORTED_IFTYPES]),
              nla_len(tb_msg[NL80211_ATTR_SUPPORTED_IFTYPES]), NULL);

    //printf("Device: %s\n", name);
    //printf("Monitor Mode: %s\n", tb_modes[NL80211_IFTYPE_MONITOR] ? "Supported" : "Not supported");
    printf("%s	%s\n", name, tb_modes[NL80211_IFTYPE_MONITOR] ? "MONITOR" : "");
    //printf("----------------------------------------\n");

    return NL_SKIP;
}

static int init_nl80211(struct nl80211_state *state) {
    state->nl_sock = nl_socket_alloc();
    if (!state->nl_sock) {
        fprintf(stderr, "Failed to allocate netlink socket.\n");
        return -1;
    }

    if (genl_connect(state->nl_sock)) {
        fprintf(stderr, "Failed to connect to generic netlink.\n");
        nl_socket_free(state->nl_sock);
        return -1;
    }

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

int main() {
    struct nl80211_state nlstate;
    struct nl_msg *msg;
    struct nl_cb *cb;
    int err;

    if (init_nl80211(&nlstate) < 0)
        return 1;

    msg = nlmsg_alloc();
    if (!msg) {
        fprintf(stderr, "Failed to allocate netlink message.\n");
        cleanup_nl80211(&nlstate);
        return 1;
    }

    cb = nl_cb_alloc(NL_CB_DEFAULT);
    if (!cb) {
        fprintf(stderr, "Failed to allocate netlink callbacks.\n");
        nlmsg_free(msg);
        cleanup_nl80211(&nlstate);
        return 1;
    }

    genlmsg_put(msg, 0, 0, nlstate.nl80211_id, 0, NLM_F_DUMP, 
                NL80211_CMD_GET_WIPHY, 0);

    nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, check_monitor_capability, NULL);
    nl_cb_err(cb, NL_CB_CUSTOM, error_handler, &err);
    nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler, &err);
    nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, ack_handler, &err);

    err = nl_send_auto_complete(nlstate.nl_sock, msg);
    if (err < 0) {
        fprintf(stderr, "Failed to send netlink message.\n");
        nl_cb_put(cb);
        nlmsg_free(msg);
        cleanup_nl80211(&nlstate);
        return 1;
    }

    err = 1;
    while (err > 0)
        nl_recvmsgs(nlstate.nl_sock, cb);

    nl_cb_put(cb);
    nlmsg_free(msg);
    cleanup_nl80211(&nlstate);

    return 0;
}
