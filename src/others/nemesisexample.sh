#!/bin/sh
  nemesis tcp -d ed0 -M "00:1c:42:db:c5:22" -H "00:1c:42:47:3f:cd" -D "192.168.1.20" -S "192.168.1.10" -fS -s 300 -x 53639 -y 22022 -v -w 65535 -T 64  -t 0 -I 1
