#!/bin/bash


#comandi per testare il traffic shaping

#tc -s -g class show dev eth0
#iperf3 -s -p 8000 -D
#iperf3 -c 141.11.126.53 -p 8000

# NOTA: LE REGOLE DI ROUTING CHE SEGUONO SONO GIÀ NEL FILE firewall-router1.conf.
# TUTTAVIA SONO LASCIATE A SCOPO DIMOSTRATIVO.

# Non posso fare il filter in uscita con un match sull'indirizzo sorgente della lan, perchè queste azioni vengono 
# eseguite dopo che i pacchetti hanno passato la chain di POSTROUTING, cioè dopo aver fatto il nat.
# Perciò con iptables metto un mark nel pacchetto a seconda della lan di provenienza e poi uso il mark per il
# match con tc-filter.


#---Marca i pacchetti della lan2 con il mark esadecimale 0x6

#---iptables -A PREROUTING -t mangle -i eth0 -j MARK --set-mark 6

#---Marca i pacchetti della lan3 con il mark esadecimale 0x7

#---iptables -A PREROUTING -t mangle -i eth2.100 -j MARK --set-mark 7


# PUNTO A

#---Attacco all'interfaccia eth5 un troncone principale con un minimo garantito e un massimo di 111mbit.
#---Questo mi serve solo come contenitore di pacchetti. Da notare che quel mbit aggiuntivo è stato specificato
#---per provare a definire una classe di default per il punto D. La classe di default viene specificato nel primo
#---comando.

tc qdisc add dev eth5 root handle 1: htb default 200
tc class add dev eth5 parent 1: classid 1:1 htb rate 111mbit ceil 111mbit burst 1Mbit cburst 1Mbit

#---Suddivido il troncone principale (in uscita verso ISP2) in tre tronconi, uno da 100mbit per la lan1,
#---l'altro da 10mbit viene condiviso per il traffico in uscita dalla lan2 e dalla lan3, e quello di default.
#---Per fare questa condivisione la classe 1:3 con un minimo garantito e un massimo di 10mbit viene suddivisa 
#---in due sottoclassi, la classe 1:31 e la classe 1:32 con un minimo garantito di 5mbit e un massimo di 10mbit.
#---La classe con id 1:2 rappresenta il troncone per il traffico in uscita dalla lan1.

tc class add dev eth5 parent 1:1 classid 1:2 htb rate 100mbit ceil 100mbit burst 1Mbit cburst 1Mbit
tc class add dev eth5 parent 1:1 classid 1:3 htb rate 10mbit ceil 10mbit burst 1Mbit cburst 1Mbit
tc class add dev eth5 parent 1:1 classid 1:200 htb rate 1mbit ceil 1mbit burst 1Mbit cburst 1Mbit

tc class add dev eth5 parent 1:3 classid 1:31 htb rate 5mbit ceil 10mbit prio 2 burst 1Mbit cburst 1Mbit
tc class add dev eth5 parent 1:3 classid 1:32 htb rate 5mbit ceil 10mbit prio 3 burst 1Mbit cburst 1Mbit

#---Poichè in uscita su eth5 il traffico viene nattato il match per la tc-filter viene fatto sul mark dei pacchetti.
#---Il mark viene impostato dal firewall a seconda della lan di provenienza: il traffico dalla lan2 ha il mark 6
#---e la regola seguente permette a questi pacchetti di finire nella classe 1:31. Il traffico della lan3 ha invece
#---il mark 7.

tc filter add dev eth5 protocol ip parent 1: prio 2 handle 6 fw flowid 1:31
tc filter add dev eth5 protocol ip parent 1: prio 3 handle 7 fw flowid 1:32

#PUNTO B

#---Dichiariamo su eth0 un troncone con un minimo e massimo da 10mbit per il traffico in ingresso sulla lan2.

tc qdisc add dev eth0 root handle 1: htb
tc class add dev eth0 parent 1: classid 1:2 htb rate 10mbit ceil 10mbit burst 1Mbit cburst 1Mbit

#---Successivamente possiamo indirizzare il traffico nella classe sopra definita con un match sulla rete di destinazione.
#---Infatti in questo caso il traffico non arriva alla lan1 nattato.

tc filter add dev eth0 protocol ip prio 1 u32 match ip dst 10.0.0.0/24 classid 1:2

#PUNTO C

#---Il ragionamento è analogo al punto b.

tc qdisc add dev eth2.100 root handle 1: htb
tc class add dev eth2.100 parent 1: classid 1:3 htb rate 10mbit ceil 10mbit burst 1Mbit cburst 1Mbit
tc filter add dev eth2.100 protocol ip prio 1 u32 match ip dst 10.0.2.0/24 classid 1:3



#PUNTO D

#---Avendo già specificato una classe per la lan1 su eth5, limitiamo ora il traffico in entrata con una classe su eth1
#---con un minimo e un massimo di 101mbit. Ancora una volta quel 1mbit è dovuto a un tentativo di definire una classe
#---di default.

tc qdisc add dev eth1 root handle 1: htb default 200
tc class add dev eth1 parent 1: classid 1:1 htb rate 101mbit ceil 101mbit burst 1Mbit cburst 1Mbit
tc class add dev eth1 parent 1:1 classid 1:2 htb rate 100mbit ceil 100mbit burst 1Mbit cburst 1Mbit
tc class add dev eth1 parent 1:1 classid 1:200 htb rate 1mbit ceil 1mbit burst 1Mbit cburst 1Mbit

#PUNTO E

#PUNTO E in output

#---Poichè il target mark non ritorna, il traffico in uscita dalla lan1 generato da un dispositivo previsto 
#---matcha una qualsiasi delle regole che seguono.

#---iptables -A PREROUTING -t mangle -i eth1 -s 10.0.1.50/32 -j MARK --set-mark 50
#---iptables -A PREROUTING -t mangle -i eth1 -s 10.0.1.51/32 -j MARK --set-mark 51
#---iptables -A PREROUTING -t mangle -i eth1 -s 10.0.1.52/32 -j MARK --set-mark 52
#---iptables -A PREROUTING -t mangle -i eth1 -s 10.0.1.100/32 -j MARK --set-mark 100
#---iptables -A PREROUTING -t mangle -i eth1 -s 10.0.1.101/32 -j MARK --set-mark 101

#---Suddividiamo il troncone di 100mbit su eth5 in uscita in tanti tronconi quanti sono i dispositivi della lan1.
#---In realtà questa è una soluzione sporca: non possiamo conoscere in anticipo gli indirizzi ip dei dispositivi su
#---cui viene eseguito la parte client dhcp, a meno di non parsarli nel file del dhcp lease, soluzione che 
#---per semplicità non ho adottato. Ogni classe ha un minimo garantito di 20mbit e un massimo di 40mbit.

tc class add dev eth5 parent 1:2 classid 1:50 htb rate 20mbit ceil 40mbit prio 1 burst 1Mbit cburst 1Mbit
tc class add dev eth5 parent 1:2 classid 1:51 htb rate 20mbit ceil 40mbit prio 1 burst 1Mbit cburst 1Mbit
tc class add dev eth5 parent 1:2 classid 1:52 htb rate 20mbit ceil 40mbit prio 1 burst 1Mbit cburst 1Mbit
tc class add dev eth5 parent 1:2 classid 1:100 htb rate 20mbit ceil 40mbit prio 1 burst 1Mbit cburst 1Mbit
tc class add dev eth5 parent 1:2 classid 1:101 htb rate 20mbit ceil 40mbit prio 1 burst 1Mbit cburst 1Mbit

#---Ancora una volta per il traffico in uscita le regole di tc-filter sono state scritte con un match sul mark del 
#---pacchetto che viene inserito dal firewall.

tc filter add dev eth5 protocol ip parent 1: prio 1 handle 50 fw flowid 1:50
tc filter add dev eth5 protocol ip parent 1: prio 1 handle 51 fw flowid 1:51
tc filter add dev eth5 protocol ip parent 1: prio 1 handle 52 fw flowid 1:52
tc filter add dev eth5 protocol ip parent 1: prio 1 handle 100 fw flowid 1:100
tc filter add dev eth5 protocol ip parent 1: prio 1 handle 101 fw flowid 1:101


#PUNTO D in input

#---Per quanto riguarda il traffico in input il ragionamento è simile, anche se naturalmente viene riproposto per
#---l'interfaccia eth1. Tuttavia non ci sono regole di firewall necessarie per le regole di tc-filter in cui il match
#---viene specificato con l'indirizzo di destinazione.
#---Anche in questo caso suddividiamo il troncone su eth1 per il traffico in entrata in tante classi quanti sono i 
#---dispositivi noti della lan1. Definiamo infine una classe di default per tutti gli altri dispositivi non noti e a cui
#---viene assicurato un minimo di un mbit.

tc class add dev eth1 parent 1:2 classid 1:50 htb rate 20mbit ceil 40mbit prio 1 burst 1Mbit cburst 1Mbit
tc class add dev eth1 parent 1:2 classid 1:51 htb rate 20mbit ceil 40mbit prio 1 burst 1Mbit cburst 1Mbit
tc class add dev eth1 parent 1:2 classid 1:52 htb rate 20mbit ceil 40mbit prio 1 burst 1Mbit cburst 1Mbit
tc class add dev eth1 parent 1:2 classid 1:100 htb rate 20mbit ceil 40mbit prio 1 burst 1Mbit cburst 1Mbit
tc class add dev eth1 parent 1:2 classid 1:101 htb rate 20mbit ceil 40mbit prio 1 burst 1Mbit cburst 1Mbit


tc filter add dev eth1 protocol ip prio 1 u32 match ip dst 10.0.1.50/32 classid 1:50
tc filter add dev eth1 protocol ip prio 1 u32 match ip dst 10.0.1.51/32 classid 1:51
tc filter add dev eth1 protocol ip prio 1 u32 match ip dst 10.0.1.52/32 classid 1:52
tc filter add dev eth1 protocol ip prio 1 u32 match ip dst 10.0.1.100/32 classid 1:100
tc filter add dev eth1 protocol ip prio 1 u32 match ip dst 10.0.1.101/32 classid 1:101

#---permette di controllare il traffico della vpn, ma in modo sbagliato.

#---tc filter add dev eth5 pref 0 protocol ip u32 match ip protocol 17 0xff classid 1:101