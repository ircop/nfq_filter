nfq_filter
==========

Tool for HTTP packets filtering via nfqueue.

Requirements:

 - kernel nfqueue support
 - libnetfilter_queue >= 1.0.1
 - modern gcc compiler with C++11 support

# Install


    $ git clone https://github.com/ircop/nfq_filter.git
    $ cd nfq_filter
    $ mkdir build && cd build
    $ cmake ../
    $ make
    $
    $ cp nfq_filter /usr/local/bin/nfq_filter

### Install with nfqueue < 1.0.1

Open file nfq.cpp and replace two lines:

    --              size = nfq_get_payload(nfa, (unsigned char **)&full_packet);
    --              len = nfq_get_payload(nfa, &data);
    ++              size = nfq_get_payload(nfa, (char **)&full_packet);
    ++              len = nfq_get_payload(nfa, (char **)&data);


# Usage


- Set iptables rule:


        iptables -A PREROUTING -s x.x.x.x/y -p tcp -m tcp --dport 80 -j NFQUEUE --queue-num 0 --queue-bypass

    where x.x.x.x/y is source network (users) for http-requests filtering

- Edit config file ( /etc/nfq/nfq_filter.cfg ), at least set queue to capture and redirect url.

- Run program (or use init.d runscript in 'contrib' dir)


# . 
Donations are welcome ^)

Ya.money: 41001647090287

WMR: R963745229668

WMZ: Z774839394176

