<div align="center">
<img src="./logo.png" width="35%"/>
</div>

<div align="center">
<img src="https://img.shields.io/badge/rating-★★★★★-green.svg"/>
<img src="https://img.shields.io/badge/coverity-passing-success.svg"/>
</div>

<div align="center">
A tool to capture data packets and time-consuming analysis<br/>
一款支持捕获数据包并进行耗时分析的工具
</div>

## Introduction [介绍]

Hamburg is a tool to capture data packets and time-consuming analysis.
It implements the functions of packet capture, unpacking, and time-consuming analysis of requests.
It mainly draws on the implementation logic of tcpokit.

Hamburg是一款支持捕获数据包并进行耗时分析的工具。它主要实现了数据包捕获，数据包解码和请求耗时分析等功能, 主要借鉴了tcpkit的实现逻辑。

## Features [特性]
 
+ `capture packets [抓包]`: 
  + Can capture and save data packets to a specified file(`-o`) like using tcpdump, and support custom filters(`-e`);
  + 可以像使用tcpdump那样进行数据包的抓取并保存到指定文件(`-o`)，同时支持自定义的过滤器(`-e`)；
+ `decoding packets [解包]`: 
  + Currently it supports parsing data packets according to the `raw`/`dns`/`http`/`redis`/`memcached`/`mysql` protocol(`-m`), and the mysql support is not perfect;
  + 目前支持按照raw/dns/http/redis/memcached/mysql的协议(`-m`)去解析数据包，其中mysql支持的不是很完善；
+ `time-consuming analysis [耗时分析]`: 
  + Analyze the execution time by recording the request and reply data packets (in the absence of network delay interference), some slow requests can be printed by setting the time-consuming threshold(`-t`). Relevant statistical reports will be printed after the program ends;
  + 通过记录请求以及回复的数据包来分析执行耗时(在没有网络延迟干扰情况下), 可以通过设置耗时的阈值(`-t`)来打印一些慢速请求。程序结束后将打印相关统计报告；
+ `lua script [lua脚本]`: 
  + Can use custom lua scripts(`-x`) to process data packets to adapt to more analysis scenarios;
  + 可以使用自定义的lua脚本(`-x`)来处理数据包以适应更多的分析场景；
+ `controllable operation [可控运行]`: 
  + Terminate the program by setting the execution time(`-d`) and the number of captured packets(`-c`);
  + 通过设置执行时间(`-d`)以及抓包数量(`-c`)来终止程序；

## Usage [使用]

```bash
$ go run main.go -h

     _                     _
    | |__   __ _ _ __ ___ | |__  _   _ _ __ __ _
    | '_ \ / _' | '_' '_ \| '_ \| | | | '__/ _| |
    | | | | (_| | | | | | | |_) | |_| | | | (_| |
    |_| |_|\__,_|_| |_| |_|_.__/ \__,_|_|  \__' |
                                            |___/ 1.0

A tool to capture data packets and time-consuming analysis.

Options:

  -i string
    	monitor network card interface or offline pcap file
  -o string
    	file to save the captured package
  -s string
    	capture packets of the specified ips, split multiple with commas
  -p string
    	capture packets of the specified ports, split multiple with commas
  -m string
    	parse the contents of packets by raw/dns/http/redis/memcached/mysql (default "raw")
  -t int
    	slow request threshold, in units of millisecond (default 5)
  -c int
    	maximum number of captured packets (default 0, no limit)
  -d int
    	maximum time of captured packets, in units of second (default 60)
  -x string
    	process packets with specialed lua script
  -n int
    	maximum length of the captured data packet snaplen (default 1500)
  -e string
    	customized packet filter, the format is the same as tcpdump
  -a	show the contents of the reply packet (default false)
  -h	help
```

## License

[MIT](./LICENSE)
