package main

import (
	"encoding/json"
	"net/url"
	"strings"
	"sync"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/likexian/whois-go"
	whoisparser "github.com/likexian/whois-parser-go"
	"github.com/patrickmn/go-cache"
)

// SuspiciousDomainEventInfo suspicious Domain upload struct
type SuspiciousDomainEventInfo struct {
	Timestamp int64                 `json:"timestamp"`
	Location  string                `json:"location"`
	Event     SuspiciousDomainEvent `json:"event"`
	Action    string                `json:"action"`
}

// SuspiciousDomainEvent suspicious domain struct
type SuspiciousDomainEvent struct {
	Name    string                       `json:"name"`
	T       string                       `json:"type"`
	Reason  string                       `json:"reason"`
	Policy  int                          `json:"policy"`
	Level   int                          `json:"level"`
	Content SuspiciousDomainEventContent `json:"content"`
}

// SuspiciousDomainEventContent suspicious domain upload struct
type SuspiciousDomainEventContent struct {
	IllegalIP        string  `json:"illegalIP"`
	RegistrationDate string  `json:"registrationDate"`
	TimeLocal        string  `json:"timeLocal"`
	SrcIP            string  `json:"srcIP"`
	SrcPort          int     `json:"srcPort"`
	DestIP           string  `json:"destIP"`
	DestPort         int     `json:"destPort"`
	Host             string  `json:"host"`
	Method           string  `json:"method"`
	URI              string  `json:"uri"`
	Referrer         string  `json:"referrer"`
	UserAgent        string  `json:"userAgent"`
	RequestBodyLen   int     `json:"requestBodyLen"`
	ResponseBodyLen  int     `json:"responseBodyLen"`
	StatusCode       int     `json:"statusCode"`
	Proxied          string  `json:"proxied"`
	PostBody         string  `json:"postBody"`
	ResponseBody     string  `json:"responseBody"`
	ResponseTime     float64 `json:"responseTime"`
	During           int     `json:"during"`
}

// cache suspicious domain data
var csd = cache.New(1*time.Minute, 10*time.Minute)

// rw mutex
var sdLock = new(sync.RWMutex)

func suspiciousDomainDetect(info httpInfo) {
	uc := getURLConfig()

	host := info.host
	if host == "-" {
		return
	}
	domain := host

	u, err := url.Parse(info.uri)
	if err != nil {
		log.Errorln("url parse faild: ", err)
	} else {
		if strings.Contains(u.Path, ".") {
			s := strings.Split(u.Path, ".")
			suffix := "." + s[len(s)-1]

			if inStringSlice(uc.Data.SuspiciousDomainDetectConfig.StaticFilter, suffix) {
				return
			}
		}
	}

	hostType := isPrivateIP(host)
	if hostType {
		return
	}

	hostType = isPublicIP(host)
	if !hostType {

		url := "http://" + host
		domain = tldQuery(url)
		if domain == "" {
			return
		}

		// 如果是常见域名，不whois查询
		if _, ok := websiteRankData[domain]; ok {
			return
		}

	}

	raw, err := whois.Whois(domain)
	if err != nil {
		return
	}

	r, err := whoisparser.Parse(raw)
	if err == nil {
		if r.Registrar.CreatedDate == "" {
			return
		}
	}

	loc, _ := time.LoadLocation("Local")
	t, err := time.ParseInLocation("2006-01-02T15:04:05Z", r.Registrar.CreatedDate, loc)
	if err == nil {
		unixTime := t.Unix()
		timeNow := time.Now().Unix()

		s := timeNow - unixTime
		threshlod := uc.Data.SuspiciousDomainDetectConfig.AlreadyRegisteredDays
		alreadyRegisteredSec := threshlod * 24 * 60 * 60

		if s < alreadyRegisteredSec {
			k := domain + "_" + info.sip

			sdLock.Lock()
			_, found := csd.Get(k)
			if !found {
				csd.Set(k, 1, time.Second*time.Duration(uc.Data.SuspiciousDomainDetectConfig.TimeWindow))
				log.Infof("suspicious domain: registrar created date %s, created day threshold %d, dst: %s, src: %s, host: %s", r.Registrar.CreatedDate, threshlod, info.dip, info.sip, info.host)
				suspiciousDomainEventUpload(info, uc, r.Registrar.CreatedDate)
			}

			sdLock.Unlock()
		}

	}

}

func suspiciousDomainEventUpload(info httpInfo, uc URLConfigs, t string) {

	iae := new(SuspiciousDomainEventInfo)
	iae.Action = ""
	iae.Location = info.sip
	iae.Timestamp = time.Now().Unix()
	iae.Event.Name = "suspicious-domain"
	iae.Event.T = "bro"
	iae.Event.Reason = uc.Data.SuspiciousDomainDetectConfig.Reason
	iae.Event.Policy = 0
	iae.Event.Level = uc.Data.SuspiciousDomainDetectConfig.Level
	iae.Event.Content.RegistrationDate = t
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
	iae.Event.Content.During = uc.Data.SuspiciousDomainDetectConfig.TimeWindow

	//fmt.Println(iae)
	jsonBody, err := json.Marshal(iae)
	if err != nil {
		log.Error("suspicious domain event upload，json marshal failed:", err)
		return
	}

	httpPost(configs.uploadEventURL, jsonBody)

}
