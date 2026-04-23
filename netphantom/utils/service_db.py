"""utils/service_db.py — extended port→service name map"""
SERVICE_DB = {
    20:"ftp-data",21:"ftp",22:"ssh",23:"telnet",25:"smtp",53:"dns",67:"dhcp",
    68:"dhcp",69:"tftp",80:"http",110:"pop3",119:"nntp",123:"ntp",135:"msrpc",
    137:"netbios-ns",138:"netbios-dgm",139:"netbios-ssn",143:"imap",161:"snmp",
    179:"bgp",194:"irc",389:"ldap",443:"https",445:"microsoft-ds",465:"smtps",
    500:"isakmp",514:"syslog",515:"printer",587:"submission",631:"ipp",
    636:"ldaps",993:"imaps",995:"pop3s",1080:"socks",1194:"openvpn",
    1433:"mssql",1521:"oracle",1723:"pptp",2049:"nfs",2181:"zookeeper",
    2375:"docker",2376:"docker-tls",3000:"dev-server",3306:"mysql",
    3389:"rdp",4444:"metasploit",5432:"postgresql",5601:"kibana",
    5900:"vnc",6379:"redis",6443:"kubernetes",8080:"http-alt",
    8443:"https-alt",8888:"jupyter",9200:"elasticsearch",9300:"elasticsearch",
    27017:"mongodb",27018:"mongodb",50070:"hadoop",
}
