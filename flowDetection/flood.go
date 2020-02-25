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

// SynEventInfo syn event upload struct
type SynEventInfo struct {
	Timestamp int64    `json:"timestamp"`
	Location  string   `json:"location"`
	Event     SynEvent `json:"event"`
	Action    string   `json:"action"`
}

// SynEvent syn event upload struct
type SynEvent struct {
	Name    string          `json:"name"`
	T       string          `json:"type"`
	Reason  string          `json:"reason"`
	Policy  int             `json:"policy"`
	Level   int             `json:"level"`
	Content SynEventContent `json:"content"`
}

// SynEventContent syn event upload struct
type SynEventContent struct {
	IllegalIP string `json:"illegalIP"`
	SrcIP     string `json:"srcIP"`
	SrcPort   int    `json:"srcPort"`
	DestIP    string `json:"destIP"`
	DestPort  int    `json:"destPort"`
	SynNum    int    `json:"synNum"`
	AckNum    int    `json:"ackNum"`
	During    int    `json:"during"`
}

// UDPEventInfo udp event upload struct
type UDPEventInfo struct {
	Timestamp int64    `json:"timestamp"`
	Location  string   `json:"location"`
	Event     UDPEvent `json:"event"`
	Action    string   `json:"action"`
}

// UDPEvent udp event upload struct
type UDPEvent struct {
	Name    string          `json:"name"`
	T       string          `json:"type"`
	Reason  string          `json:"reason"`
	Policy  int             `json:"policy"`
	Level   int             `json:"level"`
	Content UDPEventContent `json:"content"`
}

// UDPEventContent udp event upload struct
type UDPEventContent struct {
	IllegalIP string `json:"illegalIP"`
	SrcIP     string `json:"srcIP"`
	SrcPort   int    `json:"srcPort"`
	DestIP    string `json:"destIP"`
	DestPort  int    `json:"destPort"`
	PkgNum    int    `json:"pkgNum"`
	During    int    `json:"during"`
}

// rw mutex
var m = new(sync.RWMutex)

// cache syn data
var cs = cache.New(5*time.Minute, 10*time.Minute)

// cache udp data
var cu = cache.New(5*time.Minute, 10*time.Minute)

func synFloodDetect(info connInfo) {

	// 当sip是公网ip是检测
	SIPType := isPublicIP(info.sip)
	if !SIPType {
		return
	}

	cKeyPrefix := info.dip + "_t_"
	historyStateLower := strings.ToLower(info.historyState)
	// store syn and syn/ack
	if strings.Contains(historyStateLower, "s") {
		cKeyName := cKeyPrefix + "s"
		increment(cs, m, cKeyName, 1)
	}
	if strings.Contains(historyStateLower, "h") {
		cKeyName := cKeyPrefix + "h"
		increment(cs, m, cKeyName, 1)
	}

	// store syn attamp and syn received
	if strings.Contains(info.connState, "SO") {
		cKeyName := cKeyPrefix + "s0"
		increment(cs, m, cKeyName, 1)
	} else if strings.Contains(info.connState, "S1") {
		cKeyName := cKeyPrefix + "s1"
		increment(cs, m, cKeyName, 1)
	}

	// store src addr and port
	dport := strconv.Itoa(info.dport)
	cKeyName := info.dip + ":" + dport + "_t_src"
	mKeyName := info.sip + ":" + dport
	setMap(cs, m, cKeyName, mKeyName)

	// store dst addr and port
	cKeyName = "tcp_dst"
	mKeyName = info.dip + ":" + dport
	setMap(cs, m, cKeyName, mKeyName)

}

func udpFloodDetect(info connInfo) {
	// 当sip是公网ip是检测
	SIPType := isPublicIP(info.sip)
	if !SIPType {
		return
	}

	cKeyPrefix := info.dip + "_u"
	// store udp packet
	increment(cu, m, cKeyPrefix, 1)

	// store src addr and port
	dport := strconv.Itoa(info.dport)
	cKeyName := info.dip + ":" + dport + "_u_src"
	mKeyName := info.sip + ":" + dport
	setMap(cu, m, cKeyName, mKeyName)

	// store dst addr and port
	cKeyName = "udp_dst"
	mKeyName = info.dip + ":" + dport
	setMap(cu, m, cKeyName, mKeyName)

	// log.Debug(info)
}

// syn flood and udp flood ticker
func floodDetectTicker() {
	go func() {
		uc := getURLConfig()
		if uc.Data.SynFloodSwitch != "on" {
			return
		}

		sConfig := uc.Data.SynFloodConfig
		tickerSyn := time.NewTicker(time.Second * time.Duration(sConfig.TimeWindow))
		for t := range tickerSyn.C {
			uc := getURLConfig()
			sConfig := uc.Data.SynFloodConfig
			v, f := cs.Get("tcp_dst")
			if !f {
				continue
			}

			vMap := v.(map[string]int)
			vSlice := sortByMapValue(vMap)
			for _, value := range vSlice {
				dstInfo := value.key
				dstSplit := strings.Split(dstInfo, ":")
				ip := dstSplit[0]
				// syn count
				var cSynCount int
				cKeyName := ip + "_t_s"
				cKeyValue, f := cs.Get(cKeyName)
				if f {
					cSynCount = cKeyValue.(int)
					/*
						if cSynCount > sConfig.SynCount {
							srcInfo := getSrcInfo(dstInfo+"_t_src", cs)
							log.Infof("syn flood: number of syn(%d) greater than threshold %d, dst: %s, src: %s, at: %s", cSynCount, sConfig.SynCount, dstInfo, srcInfo, t)
							break
						}
					*/
				}

				// SynAck/Syn
				var cSynAckCount int
				cKeyName = ip + "_t_h"
				cKeyValue, f = cs.Get(cKeyName)
				if f {
					cSynAckCount = cKeyValue.(int)
					percent := float32(cSynAckCount) / float32(cSynCount)
					if percent < sConfig.SynAckCountDivSynCount {
						srcInfo := getSrcInfo(dstInfo+"_t_src", cs)
						log.Infof("syn flood: syn(%f) greater than threshold %f, dst: %s, src: %s, at: %s", percent, sConfig.SynAckCountDivSynCount, dstInfo, srcInfo, t)
						synEventUpload(srcInfo, dstInfo, cSynCount, cSynAckCount, uc)
						break
					}
				}

				// synAttamp Count
				cKeyName = ip + "_t_s0"
				cKeyValue, f = cs.Get(cKeyName)
				if f {
					cSynAttampCount := cKeyValue.(int)
					if cSynAttampCount > sConfig.SynAttampCount {
						srcInfo := getSrcInfo(dstInfo+"_t_src", cs)
						log.Infof("syn flood: number of s0(%d) greater than threshold %d, dst: %s, src: %s, at: %s", cSynAttampCount, sConfig.SynAttampCount, dstInfo, srcInfo, t)
						synEventUpload(srcInfo, dstInfo, cSynCount, cSynAckCount, uc)
						break
					}
				}

				// synRcvd Count
				cKeyName = ip + "_t_s1"
				cKeyValue, f = cs.Get(cKeyName)
				if f {
					cSynRcvdCount := cKeyValue.(int)
					if cSynRcvdCount > sConfig.SynRcvdCount {
						srcInfo := getSrcInfo(dstInfo+"_t_src", cs)
						log.Infof("syn flood: number of s1(%d) greater than threshold %d, dst: %s, src: %s, at: %s", cSynRcvdCount, sConfig.SynRcvdCount, dstInfo, srcInfo, t)
						synEventUpload(srcInfo, dstInfo, cSynCount, cSynAckCount, uc)
						break
					}
				}
			}

			cs.Flush()
		}
	}()

	// udp ticker
	go func() {
		uc := getURLConfig()
		uConfig := uc.Data.UDPFloodConfig
		tickerUDP := time.NewTicker(time.Second * time.Duration(uConfig.TimeWindow))
		for t := range tickerUDP.C {
			uc := getURLConfig()
			uConfig := uc.Data.UDPFloodConfig
			v, f := cu.Get("udp_dst")
			if !f {
				continue
			}

			vMap := v.(map[string]int)
			vSlice := sortByMapValue(vMap)
			for _, value := range vSlice {
				dstInfo := value.key
				dstSplit := strings.Split(dstInfo, ":")
				ip := dstSplit[0]
				// port := dstSplit[1]
				cKeyName := ip + "_u"
				cKeyValue, f := cu.Get(cKeyName)
				if f {
					cUDPCount := cKeyValue.(int)
					if cUDPCount > uConfig.UDPCount {
						srcInfo := getSrcInfo(dstInfo+"_u_src", cu)
						log.Infof("udp flood: number of udp(%d) greater than threshold %d, dst: %s, src: %s, at: %s", cUDPCount, uConfig.UDPCount, dstInfo, srcInfo, t)
						udpEventUpload(srcInfo, dstInfo, cUDPCount, uc)
						break
					}
				}

			}

			cu.Flush()
		}
	}()

}

func synEventUpload(srcInfo string, dstInfo string, cSynCount int, cSynAckCount int, uc URLConfigs) {
	srcInfoSplit := strings.Split(srcInfo, ":")
	srcIP := srcInfoSplit[0]
	srcPort, err := strconv.Atoi(srcInfoSplit[1])
	if err != nil {

		log.Error("syn flood event upload，src port string to int failed:", err, srcInfo)
	}
	dstInfoSplit := strings.Split(dstInfo, ":")
	dstIP := dstInfoSplit[0]
	dstPort, err := strconv.Atoi(dstInfoSplit[1])
	if err != nil {
		log.Error("syn flood event upload，dst port string to int failed:", err, srcInfo)
	}

	se := new(SynEventInfo)
	se.Timestamp = time.Now().Unix()
	se.Location = dstIP
	se.Action = ""
	se.Event.Name = "syn-flood"
	se.Event.T = "bro"
	se.Event.Reason = uc.Data.SynFloodConfig.Reason
	se.Event.Policy = 0
	se.Event.Level = uc.Data.SynFloodConfig.Level
	se.Event.Content.IllegalIP = srcIP
	se.Event.Content.SrcIP = srcIP
	se.Event.Content.SrcPort = srcPort
	se.Event.Content.DestIP = dstIP
	se.Event.Content.DestPort = dstPort
	se.Event.Content.SynNum = cSynCount
	se.Event.Content.AckNum = cSynAckCount
	se.Event.Content.During = uc.Data.SynFloodConfig.TimeWindow

	jsonBody, err := json.Marshal(se)
	if err != nil {
		log.Error("syn flood event upload，json marshal failed:", err)
		return
	}

	httpPost(configs.uploadEventURL, jsonBody)

}

func udpEventUpload(srcInfo string, dstInfo string, pkgnum int, uc URLConfigs) {
	srcInfoSplit := strings.Split(srcInfo, ":")
	srcIP := srcInfoSplit[0]
	srcPort, err := strconv.Atoi(srcInfoSplit[1])
	if err != nil {
		log.Error("udp flood event upload，src port string to int failed:", err)
	}
	dstInfoSplit := strings.Split(dstInfo, ":")
	dstIP := dstInfoSplit[0]
	dstPort, err := strconv.Atoi(dstInfoSplit[1])
	if err != nil {
		log.Error("udp flood event upload，src port string to int failed:", err)
	}

	ue := new(UDPEventInfo)
	ue.Timestamp = time.Now().Unix()
	ue.Location = dstIP
	ue.Action = ""
	ue.Event.Name = "udp-flood"
	ue.Event.T = "bro"
	ue.Event.Reason = uc.Data.UDPFloodConfig.Reason
	ue.Event.Policy = 0
	ue.Event.Level = uc.Data.UDPFloodConfig.Level
	ue.Event.Content.IllegalIP = srcIP
	ue.Event.Content.SrcIP = srcIP
	ue.Event.Content.SrcPort = srcPort
	ue.Event.Content.DestIP = dstIP
	ue.Event.Content.DestPort = dstPort
	ue.Event.Content.PkgNum = pkgnum
	ue.Event.Content.During = uc.Data.UDPFloodConfig.TimeWindow

	jsonBody, err := json.Marshal(ue)
	if err != nil {
		log.Error("udp flood event upload，json marshal failed:", err)
		return
	}

	httpPost(configs.uploadEventURL, jsonBody)
}
