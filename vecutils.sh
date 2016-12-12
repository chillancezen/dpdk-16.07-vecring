#! /bin/bash

alloc_domain()
{
	if [ ! $# -eq 1 ] ;then 
		echo "too few parameter"
		exit 1
	fi
	domain=$1
	mkdir -p /var/vecring/$domain
	mkdir -p /var/vecring/$domain/huge
	mount |grep "/var/vecring/$domain/huge" >/dev/null
	if [ ! $?  -eq 0 ] ;then
		mount -t hugetlbfs hugetlbfs /var/vecring/$domain/huge -o pagesize=2m
	fi
}

dealloc_domain()
{
	if [ ! $# -eq 1 ] ;then
		echo "too few parameter"
		exit 1
	fi
	domain=$1
	mount |grep "/var/vecring/$domain/huge" >/dev/null
	if [  $?  -eq 0 ] ;then
		umount /var/vecring/$domain/huge
	fi
	rm -rf /var/vecring/$domain
}
dealloc_all_domains()
{
	for dom in `ls /var/vecring/`
	do
		dealloc_domain $dom
	done
}
display_domains()
{
	idx=0
	doms=`ls /var/vecring/`
	for dom in $doms
	do
		mount |grep "/var/vecring/$dom/huge" >/dev/null
		if [ $? -eq 0 ] ;then
			echo -n "$idx:"
			echo "domain:$dom huge-dir:mounted"
		else
			echo -n "$idx:"
			echo "domain:$dom huge-dir:un-mounted"
		fi
		idx=$((idx+1))
	done
}
realloc_domains()
{
	doms=`ls /var/vecring/`
	for dom in $doms
	do
		alloc_domain $dom
	done
}
	
link_release()
{
	if [ ! $# -eq 2 ] ;then
		echo "two few argument"
		exit 1
	fi
	domain=$1
	link=$2
	for hp in `ls "/var/vecring/$domain/huge"|grep "vecring-$link\."`
	do
		rm -f "/var/vecring/$domain/huge/$hp"
	done
	rm -f "/var/vecring/$domain/$link.metadata"
}
#alloc_domain testvnf1
#alloc_domain testvnf2
#alloc_domain testvnf2

#dealloc_all_domains
#dealloc_domain testvnf1
if [ $# -eq 0 ] ;then
	echo "two few parameter."
	exit 1
fi
case $1 in 
dom_alloc*)
	shift
	alloc_domain $@
	;;
dom_realloc*)
	realloc_domains
	;;
dom_dealloc*)
	shift
	dealloc_domain  $@
	;;
dom_clean*)
	dealloc_all_domains
	;;
dom_ls*)
	display_domains
	;;
link_release*)
	shift
	link_release $@
	;;
*)
	echo "unknown commands"
	;;
esac
