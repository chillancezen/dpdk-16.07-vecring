/*2nd vlink which decouplefunctions between dpdk and qemu via standalone agent*/
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <rte_mbuf.h>
#include <rte_ethdev.h>
#include <rte_malloc.h>
#include <rte_memcpy.h>
#include <rte_dev.h>
#include <rte_kvargs.h>
#include <rte_cycles.h>
#include "vecring_ops.h"
#include "hugepage_util.h"

#define VECRING_LINK_PREFIX "/var/vecring"
static const char*driver_name="virtual link PMD powered by libvecring";

struct vecring_pmd_private{
	struct ether_addr  mac_addrs;
	int numa_node;
	int is_master;
	int queue_size;
	char domain_name[32];
	char link_name[32];
	char huge_dir[64];
	int nr_inbound_hpages;
	int nr_outbound_hpages;
	void *dummy[0] __attribute__((aligned(64)));/*the cache line will be read mostly when doing rx/tx*/
	union{
		struct vecring_header_t *vring_inbound;
		uint64_t vring_inbound_u64;
	};
	union{
		struct vecring_header_t *vring_outbound;
		uint64_t vring_outbound_u64; 
	};
	struct rte_mempool *pool;
	uint64_t rx_packets;
	uint64_t rx_bytes;
	uint64_t tx_packets;
	uint64_t tx_bytes;
	uint64_t tx_errors;
};

static struct rte_eth_link pmd_link={
	.link_speed=ETH_SPEED_NUM_25G,
	.link_duplex=ETH_LINK_FULL_DUPLEX,
	.link_status=ETH_LINK_DOWN,
	.link_autoneg=ETH_LINK_SPEED_AUTONEG,
};
static int vecring_dev_start(struct rte_eth_dev *dev)
{
	puts("starts\n");
	dev->data->dev_link.link_status=ETH_LINK_UP;
	return 0;
}
static void vecring_dev_stop(struct rte_eth_dev *dev)
{
	dev->data->dev_link.link_status=ETH_LINK_DOWN;
}
static int vecring_dev_config(struct rte_eth_dev *dev __rte_unused)
{
	return 0;
}
static void vecring_dev_info(struct rte_eth_dev*dev __rte_unused,struct rte_eth_dev_info *dev_info)
{
	
	dev_info->driver_name=driver_name;
	dev_info->max_mac_addrs=1;
	dev_info->max_rx_pktlen=(uint32_t)-1;
	dev_info->max_rx_queues=1;
	dev_info->max_tx_queues=1;
	dev_info->min_rx_bufsize=0;
	dev_info->pci_dev=NULL;
}
static int vecring_dev_rx_queue_setup(struct rte_eth_dev* dev,
	uint16_t rx_queue_id,
	uint16_t nb_rx_desc __rte_unused,
	unsigned int socket_id __rte_unused,
	const struct rte_eth_rxconf *rx_conf __rte_unused,
	struct rte_mempool*mb_pool)
{
	struct vecring_pmd_private *priv=dev->data->dev_private;
	if(rx_queue_id)
		return -1;
	priv->pool=mb_pool;
	dev->data->rx_queues[0]=priv;
	return 0;
}
static int vlink_dev_tx_queue_setup(struct rte_eth_dev*dev,
	uint16_t tx_queue_id,
	uint16_t nb_tx_desc __rte_unused,
	unsigned int socket_id __rte_unused,
	const struct rte_eth_txconf*tx_conf __rte_unused)
{
	struct vecring_pmd_private *priv=dev->data->dev_private;
	if(tx_queue_id)
		return -1;
	dev->data->tx_queues[0]=priv;
	return 0;
}
static int vecring_dev_link_update(struct rte_eth_dev *dev __rte_unused,int wait_to_complete __rte_unused ) 
{
	return 0; 
}
static uint16_t vecring_rx(void *q, struct rte_mbuf **bufs, uint16_t nb_bufs)
{
	uint16_t nr_recved=0;
	int idx;
	struct vecring_pmd_private *priv=(struct vecring_pmd_private*)q;
	if(priv->is_master)
		nr_recved=rte_vecring_dequeues(priv->vring_outbound,bufs,nb_bufs,priv->pool);
	else 
		nr_recved=rte_vecring_dequeues(priv->vring_inbound,bufs,nb_bufs,priv->pool);
	
	priv->rx_packets+=nr_recved;
	for(idx=0;idx<nr_recved;idx++)
		priv->rx_bytes+=bufs[idx]->pkt_len;
	
	return nr_recved;
}
static uint16_t vecring_tx(void *q, struct rte_mbuf **bufs, uint16_t nb_bufs)
{
	uint16_t nr_sent=0;
	int offset=0;
	int idx=0;
	struct rte_mbuf * mbuf;
	/*check frame_size,ignore any frame whose size is larger baby giant frame size*/
	/*rerrange the mbuf arrays*/
	for(;idx<nb_bufs;idx++){
		if(bufs[idx]->pkt_len>=1600){
			mbuf=bufs[offset];
			bufs[offset]=bufs[idx];
			bufs[idx]=mbuf;
			offset++;
		}
	}
	nr_sent=offset;
	struct vecring_pmd_private *priv=(struct vecring_pmd_private*)q;
	if(priv->is_master)
		nr_sent+=rte_vecring_enqueues(priv->vring_inbound,&bufs[offset],nb_bufs-offset);
	else
		nr_sent+=rte_vecring_enqueues(priv->vring_outbound,&bufs[offset],nb_bufs-offset);
	priv->tx_packets+=nr_sent-(uint16_t)offset;
	priv->tx_errors+=offset;
	for(idx=0;idx<nr_sent;idx++){
		priv->tx_bytes+=bufs[idx]->pkt_len;
		rte_pktmbuf_free(bufs[idx]);
	}
	
	return nr_sent;
}
static void vecring_dev_stats_reset(struct rte_eth_dev *dev)
{
	struct vecring_pmd_private *priv=dev->data->dev_private;
	priv->rx_bytes=0;
	priv->rx_packets=0;
	priv->tx_bytes=0;
	priv->tx_packets=0;
	priv->tx_errors=0;
}
static void vecring_dev_stats_get(struct rte_eth_dev *dev,struct rte_eth_stats *stat)
{
	struct vecring_pmd_private *priv=dev->data->dev_private;
	stat->ibytes=priv->rx_bytes;
	stat->ipackets=priv->rx_packets;
	stat->obytes=priv->tx_bytes;
	stat->opackets=priv->tx_packets;
	stat->oerrors=priv->tx_errors;
}

static struct eth_dev_ops dev_ops={
	.dev_start=vecring_dev_start,
	.dev_stop=vecring_dev_stop,
	.dev_configure=vecring_dev_config,
	.dev_infos_get=vecring_dev_info,
	.stats_get=vecring_dev_stats_get,
	.stats_reset=vecring_dev_stats_reset,
	.rx_queue_setup=vecring_dev_rx_queue_setup,
	.tx_queue_setup=vlink_dev_tx_queue_setup,
	.rx_queue_release=NULL,
	.tx_queue_release=NULL,
	.link_update=vecring_dev_link_update,
	
};
#define ETH_VECRING_ARG_SOCKET "socket" /*optional:default=0*/
#define ETH_VECRING_ARG_MAC "mac" 		/*optional:default=<randomized>*/
#define ETH_VECRING_ARG_MASTER "master" /*optional:default=TRUE*/
#define ETH_VECRING_ARG_QUEUE "queue"   /*optional:default=DEFAULT_NR_BLOCK64*/
#define ETH_VECRING_ARG_DOMAIN "domain"
#define ETH_VECRING_ARG_LINK "link"
#define ETH_VECRING_ARG_HUGEDIR "huge_dir" /*deprecated*/

static const char*valid_arguments[]={
	ETH_VECRING_ARG_SOCKET,
	ETH_VECRING_ARG_MAC,
	ETH_VECRING_ARG_MASTER,
	ETH_VECRING_ARG_QUEUE,
	ETH_VECRING_ARG_DOMAIN,
	/*ETH_VECRING_ARG_HUGEDIR,*/
	ETH_VECRING_ARG_LINK,
	NULL,
};




static int argument_callback_int(const char* key __rte_unused,const char*value,void*extra)
{
	*((int*)extra)=atoi(value);
	return 0;
}
static int argument_callback_string(const char* key __rte_unused,const char*value,void*extra)
{
	sprintf((char*)extra,"%s%c",value,'\0');
	return 0;
}

static int argument_callback_mac(const char* key __rte_unused,const char*value,void*extra)
{
	char *ptr=(char*)extra;
	sscanf(value,"%x:%x:%x:%x:%x:%x",(int*)(ptr+0),(int*)(ptr+1),(int*)(ptr+2),(int*)(ptr+3),(int*)(ptr+4),(int*)(ptr+5));
	return 0;
}
static int argument_callback_check_opt(const char* key __rte_unused,const char*value __rte_unused,void*extra)
{
	*(int*)extra=1;
	return 0;
}
static int __allocate_channel_memory(struct vecring_pmd_private *priv)
{
	int idx;
	int rc;
	char buffer[256];
	char metadata_path[256];
	FILE *fp=NULL;
	struct hugepage_memory hp_in;
	struct hugepage_memory hp_out;
	struct hugepage_memory *hp_inbound=&hp_in;
	struct hugepage_memory *hp_outbound=&hp_out;
	memset(&hp_in,0x0,sizeof(struct hugepage_memory));
	memset(&hp_out,0x0,sizeof(struct hugepage_memory));
	/*1.allocate inbound direction channel*/
	memset(buffer,0x0,sizeof(buffer));
	sprintf(buffer,"%s.inbound%c",priv->link_name,'\x0');
	rc=allocate_mmeory_from_hugepage_fs(hp_inbound,
		priv->huge_dir,
		buffer,
		needed_memory(priv->queue_size),
		priv->numa_node);
	if(rc)
		return rc;/*in case hp_outbound is not yet initialized,just return if any errors happens */

	/*2.allocate outbound direction channel*/
	memset(buffer,0x0,sizeof(buffer));
	sprintf(buffer,"%s.outbound%c",priv->link_name,'\x0');
	rc=allocate_mmeory_from_hugepage_fs(hp_outbound,
		priv->huge_dir,
		buffer,
		needed_memory(priv->queue_size),
		priv->numa_node);
	if(rc)
		goto fails;

	/*3.generate metadata file:link_name.metadata*/
	memset(metadata_path,0x0,sizeof(metadata_path));
	sprintf(metadata_path,"%s/%s/%s.metadata",VECRING_LINK_PREFIX,priv->domain_name,priv->link_name);
	fp=fopen(metadata_path,"w+");
	if(!fp)
		goto fails;
	fprintf(fp,"%d %d\n",hp_inbound->nr_files,hp_outbound->nr_files);
	for(idx=0;idx<hp_inbound->nr_files;idx++)
		fprintf(fp,"%s\n",hp_inbound->hp_files[idx].path);
	for(idx=0;idx<hp_outbound->nr_files;idx++)
		fprintf(fp,"%s\n",hp_outbound->hp_files[idx].path);
	fflush(fp);
	fclose(fp);

	/*4.update private*/
	priv->nr_inbound_hpages=hp_inbound->nr_files;
	priv->nr_outbound_hpages=hp_outbound->nr_files;
	priv->vring_inbound_u64=hp_inbound->base;
	priv->vring_outbound_u64=hp_outbound->base;
	if(hp_inbound->hp_files)
		free(hp_inbound->hp_files);
	if(hp_outbound->hp_files)
		free(hp_outbound->hp_files);
	
	return 0;
	fails:
		if(hp_inbound->hp_files)
			free_hugepage_files(hp_inbound->hp_files,hp_inbound->nr_files);
		if(hp_outbound->hp_files)
			free_hugepage_files(hp_outbound->hp_files,hp_outbound->nr_files);
		return -1;
}
static int __load_channel_memory(struct vecring_pmd_private *priv)
{
	int idx=0,idx_tmp;
	int ret=0;
	char buffer[256];
	char metadata_path[256];
	uint64_t base_in,base_out;
	FILE *fp;
	int nr_in=0,nr_out=0;
	memset(metadata_path,0x0,sizeof(metadata_path));
	sprintf(metadata_path,"%s/%s/%s.metadata",VECRING_LINK_PREFIX,priv->domain_name,priv->link_name);
	fp=fopen(metadata_path,"r");
	if(!fp)
		return -1;
	/*1.first line tell how many hugepages file each vring has*/
	if(!fgets(buffer,sizeof(buffer),fp))
		goto fails;
	sscanf(buffer,"%d%d",&nr_in,&nr_out);
	if(!nr_in || !nr_out)
		goto fails;
	
	priv->nr_inbound_hpages=nr_in;
	priv->nr_outbound_hpages=nr_out;
	/*2.map the inbound direction hugepages*/
	base_in=preserve_vm_area(nr_in,NULL);
	if(!base_in)
		goto fails;
	for(idx=0;idx<nr_in;idx++){
		int fd;
		uint64_t addr;
		memset(buffer,0x0,sizeof(buffer));
		if(!fgets(buffer,sizeof(buffer),fp))
			goto loop_fails;
		for(idx_tmp=0;idx_tmp<(int)sizeof(buffer);idx_tmp++)
			if(buffer[idx_tmp]=='\n')
				buffer[idx_tmp]='\0';
		fd=open(buffer,O_RDWR,0);
		if(fd<0)
			goto loop_fails;
		addr=(uint64_t)mmap((void*)(base_in+idx*HUGEPAGE_2M),
			HUGEPAGE_2M,
			PROT_READ|PROT_WRITE,
			MAP_SHARED|MAP_POPULATE,
			fd,
			0);
		close(fd);
		if(addr!=(base_in+idx*HUGEPAGE_2M))
			goto loop_fails;
		continue;
		loop_fails:
			for(idx_tmp=0;idx_tmp<idx;idx_tmp++)
				munmap((void*)(base_in+(HUGEPAGE_2M*idx_tmp)),HUGEPAGE_2M);
			break;
	}
	if(idx<nr_in)
		goto fails;
	/*3.map the outbound direction hugepages*/
	base_out=preserve_vm_area(nr_out,NULL);
	if(!base_out)
		goto fails;
	for(idx=0;idx<nr_out;idx++){
		int fd;
		uint64_t addr;
		memset(buffer,0x0,sizeof(buffer));
		if(!fgets(buffer,sizeof(buffer),fp))
			goto loop_fails1;
		for(idx_tmp=0;idx_tmp<(int)sizeof(buffer);idx_tmp++)
			if(buffer[idx_tmp]=='\n')
				buffer[idx_tmp]='\0';
		fd=open(buffer,O_RDWR,0);
		if(fd<0)
			goto loop_fails1;
		addr=(uint64_t)mmap((void*)(base_out+idx*HUGEPAGE_2M),
			HUGEPAGE_2M,
			PROT_READ|PROT_WRITE,
			MAP_SHARED|MAP_POPULATE,
			fd,
			0);
		close(fd);
		if(addr!=(base_out+idx*HUGEPAGE_2M))
			goto loop_fails1;
		continue;
		loop_fails1:
			for(idx_tmp=0;idx_tmp<idx;idx_tmp++)
				munmap((void*)(base_out+(HUGEPAGE_2M*idx_tmp)),HUGEPAGE_2M);
			break;
	}
	if(idx<nr_out){
		/*still need to previously installed mapping*/
		for(idx_tmp=0;idx_tmp<nr_in;idx_tmp++)
			munmap((void*)(base_in+(HUGEPAGE_2M*idx_tmp)),HUGEPAGE_2M);
		goto fails;
	}
	priv->vring_inbound_u64=base_in;
	priv->vring_outbound_u64=base_out;
	norm_flag:
		fclose(fp);
		return ret;
	fails:
		ret=-1;
		goto norm_flag;
}
static int __vecring_channels_init(struct vecring_pmd_private *priv)
{	
	int rc=0;
	rc=__load_channel_memory(priv);
	if(priv->is_master){/*only master initialize virtual vec-ring*/
		if(rc)
			rc=__allocate_channel_memory(priv);
		if(!rc){
			vecring_init(priv->vring_inbound,priv->queue_size);
			vecring_init(priv->vring_outbound,priv->queue_size);
		}
	}
	return rc;
}
static int rte_pmd_vecring_dev_init(const char*name,const char* params)
{
	struct rte_eth_dev * eth_dev=NULL;
	struct rte_eth_dev_data *data=NULL;
	struct vecring_pmd_private *priv=NULL;
	char mac[6]={'\x00'};
	int socket_id=0;
	int queue_size=DEFAULT_NR_BLOCK64;
	int is_master=0;
	char domain_name[32]={'\x00'};
	char link_name[32]={'\x00'};
	/*char huge_dir[64]={"/dev/hugepages"};*/
	
	/*resolve arguments first*/
	struct rte_kvargs *kvlist;
	kvlist=rte_kvargs_parse(params,valid_arguments);
	if(!kvlist)
		return -1;
	rte_kvargs_process(kvlist,ETH_VECRING_ARG_SOCKET,argument_callback_int,&socket_id);
	rte_kvargs_process(kvlist,ETH_VECRING_ARG_QUEUE,argument_callback_int,&queue_size);
	rte_kvargs_process(kvlist,ETH_VECRING_ARG_MASTER,argument_callback_check_opt,&is_master);
	rte_kvargs_process(kvlist,ETH_VECRING_ARG_MAC,argument_callback_mac,mac);
	rte_kvargs_process(kvlist,ETH_VECRING_ARG_DOMAIN,argument_callback_string,domain_name);
	rte_kvargs_process(kvlist,ETH_VECRING_ARG_LINK,argument_callback_string,link_name);
	/*rte_kvargs_process(kvlist,ETH_VECRING_ARG_HUGEDIR,argument_callback_string,huge_dir);*/
	rte_kvargs_free(kvlist);
	
	if(!domain_name[0] || !link_name[0])/*domain and link name must be set*/
		return -1;
	
	eth_dev=rte_eth_dev_allocate(name,RTE_ETH_DEV_VIRTUAL);
	if(!eth_dev)
		goto fails;
	data=rte_zmalloc(name,sizeof(struct rte_eth_dev_data),64);
	if(!data)
		goto fails;
	priv=rte_zmalloc(name,sizeof(struct vecring_pmd_private),64);
	if(!priv)
		goto fails;
	
	priv->numa_node=socket_id;
	priv->is_master=is_master;
	priv->queue_size=queue_size;
	strcpy(priv->domain_name,domain_name);
	strcpy(priv->link_name,link_name);
	/*strcpy(priv->huge_dir,huge_dir);*/
	sprintf(priv->huge_dir,"%s/%s/huge",VECRING_LINK_PREFIX,domain_name);
	memcpy(priv->mac_addrs.addr_bytes,mac,6);
	if(__vecring_channels_init(priv)){
		printf("[%s][error]something is wrong with vec-ring allocator\n",name);
		goto fails;
	}
	
	printf("[%s][info]                huge dir:%s\n",name,priv->huge_dir);
	printf("[%s][info]          numa socket id:%d\n",name,priv->numa_node);
	printf("[%s][info]ring buff block64 length:%d\n",name,priv->queue_size);
	printf("[%s][info]                pmd role:%s\n",name,priv->is_master?"master":"slave");
	printf("[%s][info]               link name:%s\n",name,priv->link_name);
	printf("[%s][info]             domain name:%s\n",name,priv->domain_name);
	printf("[%s][info]           mac addr:%02x:%02x:%02x:%02x:%02x:%02x\n",name,
		priv->mac_addrs.addr_bytes[0],
		priv->mac_addrs.addr_bytes[1],
		priv->mac_addrs.addr_bytes[2],
		priv->mac_addrs.addr_bytes[3],
		priv->mac_addrs.addr_bytes[4],
		priv->mac_addrs.addr_bytes[5]);
	printf("[%s][info]   vring-inbound mapping:%p\n",name,priv->vring_inbound);
	printf("[%s][info]  vring-outbound mapping:%p\n",name,priv->vring_outbound);
	
	data->dev_private=priv;
	data->port_id=eth_dev->data->port_id;
	data->nb_rx_queues=1;
	data->nb_tx_queues=1;
	data->dev_link=pmd_link;
	data->mac_addrs=&priv->mac_addrs;
	data->dev_flags=RTE_ETH_DEV_DETACHABLE;
	data->kdrv=RTE_KDRV_NONE;
	data->drv_name=driver_name;
	data->numa_node=priv->numa_node;
	strncpy(data->name,eth_dev->data->name,strlen(eth_dev->data->name));

	eth_dev->data=data;
	eth_dev->driver=NULL;
	eth_dev->dev_ops=&dev_ops;
	TAILQ_INIT(&eth_dev->link_intr_cbs);
	eth_dev->rx_pkt_burst=vecring_rx;
	eth_dev->tx_pkt_burst=vecring_tx;
	return 0;
	fails:
		
		if(priv){
			if(priv->vring_inbound)
				munmap(priv->vring_inbound,priv->nr_inbound_hpages*HUGEPAGE_2M);
			if(priv->vring_outbound)
				munmap(priv->vring_outbound,priv->nr_outbound_hpages*HUGEPAGE_2M);
			rte_free(priv);
		}
		if(data)
			rte_free(data);
		if(eth_dev)
			rte_eth_dev_release_port(eth_dev);
		return -1;
}
static int rte_pmd_vecring_dev_uninit(const char*name)
{
	struct rte_eth_dev  *eth_dev=NULL;
	struct vecring_pmd_private *private=NULL;
	eth_dev=rte_eth_dev_allocated(name);
	if(!eth_dev)
		return -1;
	private=(struct vecring_pmd_private*)eth_dev->data->dev_private;
	/*1.release private relevant data structure*/
	if(private){
		if(private->vring_inbound)
				munmap(private->vring_inbound,private->nr_inbound_hpages*HUGEPAGE_2M);
			if(private->vring_outbound)
				munmap(private->vring_outbound,private->nr_outbound_hpages*HUGEPAGE_2M);
		rte_free(private);
	}
	if(eth_dev->data)
		rte_free(eth_dev->data);
	rte_eth_dev_release_port(eth_dev);
	printf("port un init:%s\n",name);
	return 0;
}



static struct rte_driver pmd_vecring_drv={
	.type=PMD_VDEV,
	.init=rte_pmd_vecring_dev_init,
	.uninit=rte_pmd_vecring_dev_uninit,
};
PMD_REGISTER_DRIVER(pmd_vecring_drv,eth_vecring);




