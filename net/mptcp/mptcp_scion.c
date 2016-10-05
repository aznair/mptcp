#include <linux/module.h>

#include <net/mptcp.h>
#include <net/mptcp_v4.h>

#if IS_ENABLED(CONFIG_IPV6)
#include <net/mptcp_v6.h>
#endif

struct scion_priv {
	/* Worker struct for subflow establishment */
	struct work_struct subflow_work;

	struct mptcp_cb *mpcb;
};

static int num_subflows __read_mostly = 2;
module_param(num_subflows, int, 0644);
MODULE_PARM_DESC(num_subflows, "choose the number of subflows per MPTCP connection");

#define MAX_NUM_PATHS 10
#define MAX_PATH_LEN 256
typedef uint8_t path[MAX_PATH_LEN];
static path paths[MAX_NUM_PATHS];
static int num_paths;

#define MAX_DATA_LEN 2048

static int paths_ready;

static void handle_response(struct sk_buff *skb)
{
    struct nlmsghdr *nlh = NULL;
    uint8_t *ptr = NULL;

    if (paths_ready)
        return;

    nlh = (struct nlmsghdr *)skb->data;
    ptr = (uint8_t *)NLMSG_DATA(nlh);

    num_paths = 5;
    paths_ready = 1;
    wake_up_interruptible(&skb->sk->sk_wq->wait);
}

int get_paths(int isd, int as)
{
    struct sock *nl_sk = NULL;
    struct sk_buff *skb = NULL;
    struct nlmsghdr *nlh = NULL;
    uint8_t *ptr;
    struct netlink_kernel_cfg cfg = {
        .input = handle_response,
    };

    paths_ready = 0;

    /* setup and broadcast path request */
    nl_sk = netlink_kernel_create(&init_net, NETLINK_SCION, &cfg);
    skb = alloc_skb(NLMSG_SPACE(MAX_DATA_LEN), GFP_KERNEL);
    nlh = (struct nlmsghdr *)skb->data;
    nlh->nlmsg_len = NLMSG_SPACE(MAX_DATA_LEN);
    nlh->nlmsg_pid = 0;
    nlh->nlmsg_flags = 0;
    ptr = (uint8_t *)NLMSG_DATA(nlh);
    *ptr++ = 0;
    *(uint32_t *)ptr = htonl((isd << 20) | as);
    NETLINK_CB(skb).dst_group = 1;
    netlink_broadcast(nl_sk, skb, 0, 1, GFP_KERNEL);

    wait_event_interruptible(nl_sk->sk_wq->wait, paths_ready);

    return num_paths;
}

/**
 * Create all new subflows, by doing calls to mptcp_initX_subsockets
 *
 * This function uses a goto next_subflow, to allow releasing the lock between
 * new subflows and giving other processes a chance to do some work on the
 * socket and potentially finishing the communication.
 **/
static void create_subflow_worker(struct work_struct *work)
{
	const struct scion_priv *pm_priv = container_of(work,
						     struct scion_priv,
						     subflow_work);
	struct mptcp_cb *mpcb = pm_priv->mpcb;
	struct sock *meta_sk = mpcb->meta_sk;
	int iter = 0;

    /* TODO: isd_as should be somewhere in struct sock */
    get_paths(1, 13);

next_subflow:
	if (iter) {
		release_sock(meta_sk);
		mutex_unlock(&mpcb->mpcb_mutex);

		cond_resched();
	}
	mutex_lock(&mpcb->mpcb_mutex);
	lock_sock_nested(meta_sk, SINGLE_DEPTH_NESTING);

	iter++;

	if (sock_flag(meta_sk, SOCK_DEAD))
		goto exit;

	if (mpcb->master_sk &&
	    !tcp_sk(mpcb->master_sk)->mptcp->fully_established)
		goto exit;

	if (num_subflows > iter && num_subflows > mpcb->cnt_subflows &&
            num_paths > iter && num_paths > mpcb->cnt_subflows) {
		if (meta_sk->sk_family == AF_INET ||
		    mptcp_v6_is_v4_mapped(meta_sk)) {
			struct mptcp_loc4 loc;
			struct mptcp_rem4 rem;

			loc.addr.s_addr = inet_sk(meta_sk)->inet_saddr;
			loc.loc4_id = 0;
			loc.low_prio = 0;
            loc.if_idx = 0;

			rem.addr.s_addr = inet_sk(meta_sk)->inet_daddr;
			rem.port = inet_sk(meta_sk)->inet_dport;
			rem.rem4_id = 0; /* Default 0 */

			mptcp_init4_subsockets(meta_sk, &loc, &rem);
		} else {
#if IS_ENABLED(CONFIG_IPV6)
			struct mptcp_loc6 loc;
			struct mptcp_rem6 rem;

			loc.addr = inet6_sk(meta_sk)->saddr;
			loc.loc6_id = 0;
			loc.low_prio = 0;
            loc.if_idx = 0;

			rem.addr = meta_sk->sk_v6_daddr;
			rem.port = inet_sk(meta_sk)->inet_dport;
			rem.rem6_id = 0; /* Default 0 */

			mptcp_init6_subsockets(meta_sk, &loc, &rem);
#endif
		}
        //TODO: Add scion path to subsocket data structure here
		goto next_subflow;
	}

exit:
	release_sock(meta_sk);
	mutex_unlock(&mpcb->mpcb_mutex);
	sock_put(meta_sk);
}

static void scion_new_session(const struct sock *meta_sk)
{
	struct mptcp_cb *mpcb = tcp_sk(meta_sk)->mpcb;
	struct scion_priv *fmp = (struct scion_priv *)&mpcb->mptcp_pm[0];

	/* Initialize workqueue-struct */
	INIT_WORK(&fmp->subflow_work, create_subflow_worker);
	fmp->mpcb = mpcb;
}

static void scion_create_subflows(struct sock *meta_sk)
{
	const struct mptcp_cb *mpcb = tcp_sk(meta_sk)->mpcb;
	struct scion_priv *pm_priv = (struct scion_priv *)&mpcb->mptcp_pm[0];

	if (mpcb->infinite_mapping_snd || mpcb->infinite_mapping_rcv ||
	    mpcb->send_infinite_mapping ||
	    mpcb->server_side || sock_flag(meta_sk, SOCK_DEAD))
		return;

	if (!work_pending(&pm_priv->subflow_work)) {
		sock_hold(meta_sk);
		queue_work(mptcp_wq, &pm_priv->subflow_work);
	}
}

static int scion_get_local_id(sa_family_t family, union inet_addr *addr,
				   struct net *net, bool *low_prio)
{
	return 0;
}

static struct mptcp_pm_ops scion __read_mostly = {
	.new_session = scion_new_session,
	.fully_established = scion_create_subflows,
	.get_local_id = scion_get_local_id,
	.name = "scion",
	.owner = THIS_MODULE,
};

/* General initialization of MPTCP_PM */
static int __init scion_register(void)
{
	BUILD_BUG_ON(sizeof(struct scion_priv) > MPTCP_PM_SIZE);

	if (mptcp_register_path_manager(&scion))
		goto exit;

	return 0;

exit:
	return -1;
}

static void scion_unregister(void)
{
	mptcp_unregister_path_manager(&scion);
}

module_init(scion_register);
module_exit(scion_unregister);

MODULE_AUTHOR("Jason Lee");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("SCION MPTCP");
MODULE_VERSION("0.1");
