package main

import (
	"encoding/json"
	"strconv"
	"strings"
	"sync"

	"time"

	log "github.com/Sirupsen/logrus"
	_ "github.com/go-sql-driver/mysql"
	"github.com/patrickmn/go-cache"
)

// ScanEventInfo scan event upload struct
type ScanEventInfo struct {
	Timestamp int64     `json:"timestamp"`
	Location  string    `json:"location"`
	Event     ScanEvent `json:"event"`
	Action    string    `json:"action"`
}

// ScanEvent scan event upload struct
type ScanEvent struct {
	Name    string           `json:"name"`
	T       string           `json:"type"`
	Reason  string           `json:"reason"`
	Policy  int              `json:"policy"`
	Level   int              `json:"level"`
	Content ScanEventContent `json:"content"`
}

// ScanEventContent scan event upload struct
type ScanEventContent struct {
	IllegalIP string   `json:"illegalIP"`
	SrcIP     string   `json:"srcIP"`
	DestIP    []string `json:"destIP"`
	DestIPnum int      `json:"destIPnum"`
	During    int      `json:"during"`
}

// cache scan data
var cscan = cache.New(5*time.Minute, 10*time.Minute)

func scanDetect(info connInfo) {
	SIPType := isPublicIP(info.sip)
	DIPType := isPublicIP(info.dip)

	// 内网地址扫描，当sip和dip都是内网地址时进行检测
	if !SIPType && !DIPType {

		k := info.sip
		cacheV := info.dip + ":" + strconv.Itoa(info.dport) + ":" + strings.ToUpper(info.transportLayerProtocol) + ":" + strings.ToUpper(info.applicationProtocol)
		//cacheV := info.dip

		var slock = new(sync.RWMutex)

		slock.Lock()
		v, f := cscan.Get(k)
		if !f {
			tmpSlice := []string{
				cacheV,
			}
			cscan.Set(k, tmpSlice, cache.DefaultExpiration)

		} else {
			cValue := v.([]string)
			if !inStringSlice(cValue, cacheV) {
				cValue = append(cValue, cacheV)
				cscan.Set(k, cValue, cache.DefaultExpiration)
			}
		}

		slock.Unlock()

	}

}

// syn flood and udp flood ticker
func scanTicker() {
	// scan ticker
	go func() {
		uc := getURLConfig()
		if uc.Data.ScanSwitch != "on" {
			return
		}

		tickerUDP := time.NewTicker(time.Second * time.Duration(uc.Data.ScanConfig.TimeWindow))
		for t := range tickerUDP.C {
			uc := getURLConfig()
			m := cscan.Items()
			for k, v := range m {

				vSlice := v.Object.([]string)
				var destIP []string
				for _, vv := range vSlice {
					dip := strings.Split(vv, ":")[0]
					destIP = append(destIP, dip)
				}

				destIPLen := len(destIP)
				if destIPLen > uc.Data.ScanConfig.DstAddrCount {
					log.Infof("scan address: count of dst addr(%d) greater than threshold %d, dst: %s, src: %s, at: %s", destIPLen, uc.Data.ScanConfig.DstAddrCount, k, v.Object, t)
					scanEventUpload(vSlice, k, uc)
				}
			}

			cscan.Flush()
		}
	}()
}

func scanEventUpload(dstAddress []string, srcIP string, uc URLConfigs) {
	se := new(ScanEventInfo)
	se.Action = ""
	se.Location = srcIP
	se.Timestamp = time.Now().Unix()
	se.Event.Name = "scan-address"
	se.Event.T = "bro"
	se.Event.Reason = uc.Data.ScanConfig.Reason
	se.Event.Policy = 0
	se.Event.Level = uc.Data.ScanConfig.Level
	se.Event.Content.IllegalIP = srcIP
	se.Event.Content.SrcIP = srcIP
	se.Event.Content.DestIP = dstAddress
	se.Event.Content.DestIPnum = len(dstAddress)
	se.Event.Content.During = uc.Data.ScanConfig.TimeWindow

	jsonBody, err := json.Marshal(se)
	if err != nil {
		log.Error("scan event upload，json marshal failed:", err)
		return
	}

	httpPost(configs.uploadEventURL, jsonBody)
}
