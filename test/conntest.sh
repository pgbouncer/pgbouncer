#!/bin/sh

fw_drop_port() {
        echo "fw_drop_port"
	case `uname` in
	Linux)
		sudo iptables -A OUTPUT -p tcp --dport $1 -j DROP;;
	Darwin|OpenBSD)
		echo "block drop out proto tcp from any to 127.0.0.1 port $1" \
		    | sudo pfctl -a pgbouncer -f -;;
	*)
		echo "Unknown OS";;
	esac
}
fw_reject_port() {
        echo "fw_reject_port"
	case `uname` in
	Linux)
		sudo iptables -A OUTPUT -p tcp --dport $1 -j REJECT --reject-with tcp-reset;;
	Darwin|OpenBSD)
		echo "block return-rst out proto tcp from any to 127.0.0.1 port $1" \
		    | sudo pfctl -a pgbouncer -f -;;
	*)
		echo "Unknown OS";;
	esac
}

fw_reset() {
        echo "fw_reset"
	case `uname` in
	Linux)
		sudo iptables -F;;
	Darwin|OpenBSD)
		sudo pfctl -a pgbouncer -F all;;
	*)
		echo "Unknown OS"; exit 1;;
	esac
}

port=5432
port=7000

fw_reset

while true; do
  fw_drop_port $port
  sleep 12
  fw_reset
  sleep 12
  fw_reject_port $port
  sleep 3
  fw_reset
  sleep 6
done
