<div align="center">
<img src="./assets/logo.png" width="35%"/>
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

Hamburg是一款支持捕获数据包并进行耗时分析的工具。它主要实现了数据包捕获，数据包解码和请求耗时分析等功能, 主要借鉴了[tcpkit](https://github.com/git-hulk/tcpkit)的实现逻辑。

## Features [特性]
 
+ `capture packets [抓包]`:
  + Can capture and save data packets to a specified file(`-o`) like using tcpdump, and support custom filters(`-e`);
  + 可以像使用tcpdump那样进行数据包的抓取并保存到指定文件(`-o`)，同时支持自定义的过滤器(`-e`)；
+ `decoding packets [解包]`:
  + Currently it supports parsing data packets according to the `raw`/`dns`/`http`/`redis`/`memcached`/`mysql` protocol(`-m`), and the mysql support is not perfect;
  + 目前支持按照`raw`/`dns`/`http`/`redis`/`memcached`/`mysql`的协议(`-m`)去解析数据包，其中mysql支持的不是很完善；
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
        monitor network interface or offline pcap file
  -o string
        outfile for the captured package
  -s string
        filtered ip list, splited with commas
  -p string
        filtered port list, splited with commas
  -m string
        packet protocol type with raw/dns/http/redis/memcached/mysql (default "raw")
  -t int
        threshold for slow requests (millisecond) (default 1)
  -d int
        running time for capturing packets (second), (default unlimited)
  -x string
        lua script file
  -n int
        maximum length of the captured data packet snaplen (default 1500)
  -e string
        customized packet filter
  -a    show the contents of the reply packet (default false)
  -h    help
```

## Examples [示例]

#### raw

```bash
$ go run main.go -i en0 -m raw -t 0

Name:  en0
Description:
Devices addresses:
- IP address: 192.168.1.101
- Subnet mask:  ffffff00

Start capturing packet with filter:
2020-07-26 10:01:04 ||   33.215.6.487:12702 =>   192.168.1.101:10000 || 74µs || Seq:375122483 - Ack:384355757 - PSH,ACK - PayLen:472
2020-07-26 10:01:04 ||   33.215.6.487:53823 =>   192.168.1.101:10000 || 71µs || Seq:3601459005 - Ack:1117436923 - PSH,ACK - PayLen:105
2020-07-26 10:01:04 ||   33.215.6.487:38304 =>   192.168.1.101:10000 || 152µs || Seq:1549571396 - Ack:3127071304 - PSH,ACK - PayLen:65
2020-07-26 10:01:04 ||   33.215.6.487:62119 =>   192.168.1.101:10000 || 70µs || Seq:3259862010 - Ack:2427343399 - PSH,ACK - PayLen:472
```


#### dns

```bash
$ go run main.go -i en0 -s 192.168.1.101 -p 53 -m dns -t 0 -a

Name:  en0
Description:
Devices addresses:
- IP address: 192.168.1.101
- Subnet mask:  ffffff00

Start capturing packet with filter: ((port 53) and ((host192.168.1.101)))
2020-07-26 11:17:30 ||  192.168.1.101:45742 =>       223.5.5.5:53    || 155µs || [AAAA] manshs1.tsdmain.org ||
2020-07-26 11:17:30 ||  192.168.1.101:25138 =>       223.5.5.5:53    || 162µs || [A] manshs1.tsdmain.org || [A] 215.33.36.57;
2020-07-26 11:17:30 ||  192.168.1.101:25138 =>  208.67.220.220:53    || 584µs || [A] manshs1.tsdmain.com || [A] 225.42.15.55;
2020-07-26 11:17:33 ||  192.168.1.101:53488 =>  208.67.220.220:53    || 575µs || [A] www.a.shifen.com || [A] 61.135.169.125/61.135.169.125;
```

#### http

```bash
$ go run main.go -i en0 -p 80 -m http -t 0 -a

Name:  en0
Description:
Devices addresses:
- IP address: 192.168.1.101
- Subnet mask:  ffffff00

Start capturing packet with filter: ((port 80))
2020-07-26 12:41:57 ||   192.168.1.101:25617 =>   221.194.147.231:80    || 1.909ms || [HTTP/1.1 GET] https://www.processon.com || [HTTP/1.1 200] Tengine
2020-07-26 12:41:58 ||   192.168.1.101:25621 =>   54.222.212.205:80    || 1.593ms || [HTTP/1.1 GET] https://zgsdk.zhugeio.com/zhuge.min.js || [HTTP/1.1 200] nginx
2020-07-26 12:41:58 ||   192.168.1.101:25623 =>   33.26.105.240:80    || 2.124ms || [HTTP/1.1 POST] www.dnsdizhi.com || [HTTP/1.1 200] nginx
2020-07-26 12:41:58 ||   192.168.1.101:25627 =>   23.226.62.190:80    || 1.809ms || [HTTP/1.1 GET] man.linuxde.net/mkisofs || [HTTP/1.1 200] openresty
```

#### redis

```bash
$ go run main.go -i en0 -s 192.168.1.101 -p 6379 -m redis -t 0

Name:  en0
Description:
Devices addresses:
- IP address: 192.168.1.101
- Subnet mask:  ffffff00

Start capturing packet with filter: ((port 6379) and ((host 192.168.1.101)))
2020-07-26 14:33:55 ||   192.168.1.203:55241 =>   192.168.1.101:50396 || 408µs || COMMAND
2020-07-26 14:33:57 ||   192.168.1.203:55241 =>   192.168.1.101:50396 || 191µs || info
2020-07-26 14:34:05 ||   192.168.1.203:55242 =>   192.168.1.101:50396 || 193µs || info memory
2020-07-26 14:34:19 ||   192.168.1.203:54311 =>   192.168.1.101:50396 || 312µs || set a 1000
```

#### memcached

```bash
$ go run main.go -i en0 -p 54325 -m memcached -t 0

Name:  en0
Description:
Devices addresses:
- IP address: 192.168.1.101
- Subnet mask:  ffffff00

Start capturing packet with filter: ((port 54325))
2020-07-26 16:08:55 ||    33.231.22.167:61096 =>   192.168.1.101:54325 || 2.983561s || add new_key 0 900 10  data_value
2020-07-26 16:09:05 ||    33.231.22.167:61096 =>   192.168.1.101:54325 || 43µs || get new_key
2020-07-26 16:09:08 ||    33.231.22.167:61096 =>   192.168.1.101:54325 || 100µs || stats
2020-07-26 16:09:23 ||    33.231.22.167:61096 =>   192.168.1.101:54325 || 349.368ms || replace mykey 0 900 16  some_other_value
2020-07-26 16:09:28 ||    33.231.22.167:61096 =>   192.168.1.101:54325 || 37µs || get mykey
```

#### mysql

```bash
$ go run main.go -i en0 -p 3306 -m mysql -t 0

Name:  en0
Description:
Devices addresses:
- IP address: 192.168.1.101
- Subnet mask:  ffffff00

Start capturing packet with filter: ((port 3306))
2020-07-26 18:57:04 ||   33.231.22.167:54966 =>     192.168.1.101:3306  || 1.325ms || SET NAMES utf8
2020-07-26 18:57:04 ||   33.231.22.167:54966 =>     192.168.1.101:3306  || 1.521ms || SELECT * FROM `idc`
2020-07-26 18:57:04 ||   33.231.22.167:54966 =>     192.168.1.101:3306  || 2.203ms || SELECT * FROM `topics`
2020-07-26 18:57:04 ||   33.231.22.167:54970 =>     192.168.1.101:3306  || 1.318ms || SELECT * FROM `frontends`  WHERE (idc = ?)
```



## License

[MIT](./LICENSE)
