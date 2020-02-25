# 一，API配置格式
说明：程序通过调用前端提供的API接口获取业务相关的配置文件，并且每隔2S会自动从API热加载配置文件，如果配置解析出错或者API接口挂掉则沿用老的配置。
```
{
    "data":{
        "assetDetectionSwitch":"off",
        "synFloodSwitch":"on",
        "udpFloodSwitch":"on",
        "synFloodConfig":{
            "synCount":30000,
            "synAttampCount":1000,
            "SynAckCountDivSynCount":0.1,
            "synRcvdCount":500,
            "level": 3,
            "reason": "syn-flood",
            "timeWindow":60
        },
        "udpFloodConfig":{
            "udpCount":1000,
            "level": 3,
            "reason": "udp-flood",
            "timeWindow":60
        },
        "scanSwitch":"on",
        "scanConfig":{
            "timeWindow":60,
            "level": 3,
            "reason": "scan-address",
            "dstAddrCount":20
        },
        "dstAddrDetectSwitch":"on",
        "dstAddrDetectConfig":{
            "timeWindow":60,
            "level": 3,
            "reason": "c2地址",
            "blackList":[
                "qq.com"
            ],
            "whiteList":[
                "www.baidu.com"
            ]
        }
    }
}
```

字段说明：
timeWindow：以秒为单位的时间窗口
level：对应异常的级别
reason：异常原因
assetDetectionSwitch：资产检测的开关
synFloodSwitch：syn flood检测的开关
udpFloodSwitch：udp flood检测的开关
synFloodConfig：syn flood的配置项
udpFloodConfig：udp flood的配置项
synFloodConfig.synCount：在timeWindow内syn包的数量
synFloodConfig.synAttampCount：在timeWindow内client发送了syn包，但是server端没有响应syn/ack包的数量
synFloodConfig.SynAckCountDivSynCount：在timeWindow内syn/ack包的数量与syn包数量的比例
synFloodConfig.synRcvdCount：在timeWindow内半连接的数量
udpFloodConfig.udpCount：在timeWindow内udp包的数量
scanSwitch：检测内网扫描的开关
scanConfig：scan的配置项
scanConfig.dstAddrCount：在timeWindow时间内访问目的地址的数量
dstAddrDetectSwitch：目的地址检测的开关
dstAddrDetectConfig：目的地址检测的配置项
dstAddrDetectConfig.blackList：目的地址检测黑名单列表，支持ip和域名
dstAddrDetectConfig.whiteList：目的地址检测白名单列表，支持ip和域名

# 二，攻击检测原理
1，syn flood
以目的ip为统计维度，在单位时间内，当目的ip相关数据满足如下条件中的一个，则认为发生syn flood。
> * syn/ack除以syn 比例小于阈值synFloodConfig.SynAckCountDivSynCount，说明syn包数量比synack包数量大很多，则认为异常；
> * syn attamp的数量大于阈值synFloodConfig.synAttampCount；
> * 半连接的数量查过一定阈值；

2,udp flood
> * 已目的ip为统计维度，在单位时间内，当目的ip收到的udp数据包数量大于udpFloodConfig.udpCount，则认为发生udp flood。

3，内网扫描
> * 当目的ip在单位时间内，被大于scanConfig.dstAddrCount数量的ip连接，则认为发生扫描

4，目的地址c2检测
> * 当目的ip或者目的域名在c2的地址库里面，则认为访问的是c2地址；
> * 当目的ip在白名单，则直接放过；
> * 当目的ip在黑名单，则直接上报；


# 三，对应攻击数据存储的数据结构
1，syn flood
```
1.1.1.2_t_s:count      //存储单位时间内单个ip syn数量
1.1.1.2_t_h:count       // 存储单位时间内单个ip syn/ack数量
1.1.1.2_t_s0:count      // 存储单位时间内单个ip syn attamp数量
1.1.1.2_t_s1:count      // 存储单位时间内单个ip syn rcvd数量
1.1.1.2:80_t_src:{1.1.1.1:1234 1,1.1.1.1:1235 2}  //存储单位时间内目的ip和port的src地址
tcp_dst:{1.1.1.2:80 3,1.1.1.2:443 4}            //存储单位时间内所有目的ip和port
```

2，udp flood
```
1.1.1.2_u:count  // 存储单位时间内单个ip udp包数量
1.1.1.2:80_u_src:{1.1.1.1:1234 1,1.1.1.1:1235 2}   //存储单位时间内目的ip和port的src地址
udp_dst:{1.1.1.2:80 3,1.1.1.2:443 4} //存储单位时间内所有目的ip和port
```