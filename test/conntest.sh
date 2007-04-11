#!/bin/sh

fw_drop_port() {
        echo "fw_drop_port"
	case `uname` in
	Linux)
		sudo iptables -A OUTPUT -p tcp --dport $1 -j DROP;;
	Darwin)
		sudo ipfw add 100 drop tcp from any to 127.0.0.1 dst-port $1;;
	*)
		echo "Unknown OS";;
	esac
}
fw_reject_port() {
        echo "fw_reject_port"
	case `uname` in
	Linux)
		sudo iptables -A OUTPUT -p tcp --dport $1 -j REJECT --reject-with tcp-reset;;
	Darwin)
		sudo ipfw add 100 reset tcp from any to 127.0.0.1 dst-port $1;;
	*)
		echo "Unknown OS";;
	esac
}

fw_reset() {
        echo "fw_reset"
	case `uname` in
	Linux)
		sudo iptables -F;;
	Darwin)
		sudo ipfw del 100;;
	*)
		echo "Unknown OS"; exit 1;;
	esac
}

port=5432
port=7000

fw_reset

while true; do
  #fw_drop_port $port
  #sleep 20
  #fw_reset
  #sleep 20
  fw_reject_port $port
  sleep 3
  fw_reset
  sleep 6
done


