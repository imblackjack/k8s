package main

import (
	"encoding/json"
	"sync"

	log "github.com/Sirupsen/logrus"

	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/patrickmn/go-cache"
)

// IllegalAddressEventInfo illegal address upload struct
type IllegalAddressEventInfo struct {
	Timestamp int64               `json:"timestamp"`
	Location  string              `json:"location"`
	Event     IllegalAddressEvent `json:"event"`
	Action    string              `json:"action"`
}

// IllegalAddressEvent illegal address upload struct
type IllegalAddressEvent struct {
	Name    string                     `json:"name"`
	T       string                     `json:"type"`
	Reason  string                     `json:"reason"`
	Policy  int                        `json:"policy"`
	Level   int                        `json:"level"`
	Content IllegalAddressEventContent `json:"content"`
}

// IllegalAddressEventContent illegal address upload struct
type IllegalAddressEventContent struct {
	IllegalIP string  `json:"illegalIP"`
	TimeLocal string  `json:"timeLocal"`
	SrcIP     string  `json:"srcIP"`
	SrcPort   int     `json:"srcPort"`
	DestIP    string  `json:"destIP"`
	DestPort  int     `json:"destPort"`
	Proto     string  `json:"proto"`
	Service   string  `json:"service"`
	Duration  float64 `json:"duration"`
	OrigBytes int     `json:"origBytes"`
	RespBytes int     `json:"respBytes"`
	ConnState string  `json:"connState"`
	History   string  `json:"history"`
	OrigPkts  int     `json:"origPkts"`
	RespPkts  int     `json:"respPkts"`
	During    int     `json:"during"`
}

// IllegalHTTPEventInfo illegal http upload struct
type IllegalHTTPEventInfo struct {
	Timestamp int64            `json:"timestamp"`
	Location  string           `json:"location"`
	Event     IllegalHTTPEvent `json:"event"`
	Action    string           `json:"action"`
}

// IllegalHTTPEvent illegal address http struct
type IllegalHTTPEvent struct {
	Name    string                  `json:"name"`
	T       string                  `json:"type"`
	Reason  string                  `json:"reason"`
	Policy  int                     `json:"policy"`
	Level   int                     `json:"level"`
	Content IllegalHTTPEventContent `json:"content"`
}

// IllegalHTTPEventContent illegal http upload struct
type IllegalHTTPEventContent struct {
	IllegalIP       string  `json:"illegalIP"`
	TimeLocal       string  `json:"timeLocal"`
	SrcIP           string  `json:"srcIP"`
	SrcPort         int     `json:"srcPort"`
	DestIP          string  `json:"destIP"`
	DestPort        int     `json:"destPort"`
	Host            string  `json:"host"`
	Method          string  `json:"method"`
	URI             string  `json:"uri"`
	Referrer        string  `json:"referrer"`
	UserAgent       string  `json:"userAgent"`
	RequestBodyLen  int     `json:"requestBodyLen"`
	ResponseBodyLen int     `json:"responseBodyLen"`
	StatusCode      int     `json:"statusCode"`
	Proxied         string  `json:"proxied"`
	PostBody        string  `json:"postBody"`
	ResponseBody    string  `json:"responseBody"`
	ResponseTime    float64 `json:"responseTime"`
	During          int     `json:"during"`
}

// cache illagel dst detect data
var ci = cache.New(1*time.Minute, 10*time.Minute)

// rw mutex
var idLock = new(sync.RWMutex)

func illegalAddressDetect(info connInfo) {
	uc := getURLConfig()

	dstAddress := info.dip
	if inStringSlice(uc.Data.DstAddrDetectConfig.WhiteList, dstAddress) {
		log.Infof("%s in dst address detect whilte list", dstAddress)
		return
	}

	if inStringSlice(uc.Data.DstAddrDetectConfig.BlackList, dstAddress) {
		illegalAddressEventUpload(info, uc)
	}

	if _, ok := illegalData[dstAddress]; ok {

		k := dstAddress + "_" + info.sip
		_, found := ci.Get(k)
		if !found {
			ci.Set(k, 1, time.Second*time.Duration(uc.Data.DstAddrDetectConfig.TimeWindow))
			illegalAddressEventUpload(info, uc)
		}
	}

}

func illegalDomainDetect(info httpInfo) {
	uc := getURLConfig()

	dstDomain := info.host
	if inStringSlice(uc.Data.DstAddrDetectConfig.WhiteList, dstDomain) {
		log.Infof("%s in dst domain detect whilte list", dstDomain)
		return
	}

	if inStringSlice(uc.Data.DstAddrDetectConfig.BlackList, dstDomain) {
		illegalDomainEventUpload(info, uc)
	}

	if _, ok := illegalData[dstDomain]; ok {

		k := dstDomain + "_" + info.sip
		sdLock.Lock()
		_, found := ci.Get(k)
		if !found {
			ci.Set(k, 1, time.Second*time.Duration(uc.Data.DstAddrDetectConfig.TimeWindow))
			illegalDomainEventUpload(info, uc)
		}
		sdLock.Unlock()
	}
}

func illegalAddressEventUpload(info connInfo, uc URLConfigs) {
	iae := new(IllegalAddressEventInfo)
	iae.Action = ""
	iae.Location = info.sip
	iae.Timestamp = time.Now().Unix()
	iae.Event.Name = "c2-address"
	iae.Event.T = "bro"
	iae.Event.Reason = uc.Data.DstAddrDetectConfig.Reason
	iae.Event.Policy = 0
	iae.Event.Level = uc.Data.DstAddrDetectConfig.Level
	iae.Event.Content.IllegalIP = info.dip
	iae.Event.Content.TimeLocal = info.time
	iae.Event.Content.SrcIP = info.sip
	iae.Event.Content.SrcPort = info.sport
	iae.Event.Content.DestIP = info.dip
	iae.Event.Content.DestPort = info.dport
	iae.Event.Content.Proto = info.transportLayerProtocol
	iae.Event.Content.Service = info.applicationProtocol
	iae.Event.Content.Duration = info.duration
	iae.Event.Content.OrigBytes = info.origBytes
	iae.Event.Content.RespBytes = info.respBytes
	iae.Event.Content.ConnState = info.connState
	iae.Event.Content.History = info.historyState
	iae.Event.Content.OrigPkts = info.origPkts
	iae.Event.Content.RespPkts = info.respPkts
	iae.Event.Content.During = uc.Data.DstAddrDetectConfig.TimeWindow

	jsonBody, err := json.Marshal(iae)
	if err != nil {
		log.Error("illegal address event upload，json marshal failed:", err)
		return
	}

	httpPost(configs.uploadEventURL, jsonBody)
}

func illegalDomainEventUpload(info httpInfo, uc URLConfigs) {
	iae := new(IllegalHTTPEventInfo)
	iae.Action = ""
	iae.Location = info.sip
	iae.Timestamp = time.Now().Unix()
	iae.Event.Name = "c2-domain"
	iae.Event.T = "bro"
	iae.Event.Reason = uc.Data.DstAddrDetectConfig.Reason
	iae.Event.Policy = 0
	iae.Event.Level = uc.Data.DstAddrDetectConfig.Level
	iae.Event.Content.IllegalIP = info.dip
	iae.Event.Content.TimeLocal = info.time
	iae.Event.Content.SrcIP = info.sip
	iae.Event.Content.SrcPort = info.sport
	iae.Event.Content.DestIP = info.dip
	iae.Event.Content.DestPort = info.dport
	iae.Event.Content.Host = info.host
	iae.Event.Content.Method = info.method
	iae.Event.Content.URI = info.uri
	iae.Event.Content.Referrer = info.referer
	iae.Event.Content.UserAgent = info.userAgent
	iae.Event.Content.RequestBodyLen = info.requestBodyLen
	iae.Event.Content.ResponseBodyLen = info.responseBodyLen
	iae.Event.Content.StatusCode = info.statusCode
	iae.Event.Content.Proxied = info.proxied
	iae.Event.Content.PostBody = info.postBody
	iae.Event.Content.ResponseBody = info.responseBody
	iae.Event.Content.ResponseTime = info.responseTime
	iae.Event.Content.During = uc.Data.DstAddrDetectConfig.TimeWindow

	jsonBody, err := json.Marshal(iae)
	if err != nil {
		log.Error("illegal domain event upload，json marshal failed:", err)
		return
	}

	httpPost(configs.uploadEventURL, jsonBody)
}
