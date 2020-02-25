package main

import (
	"encoding/json"
	"net"
	"strings"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/oschwald/geoip2-golang"
	"github.com/patrickmn/go-cache"
)

// DataSuspiciousTransferEventInfo data suspicious transfer upload struct
type DataSuspiciousTransferEventInfo struct {
	Timestamp int64                       `json:"timestamp"`
	Location  string                      `json:"location"`
	Event     DataSuspiciousTransferEvent `json:"event"`
	Action    string                      `json:"action"`
}

// DataSuspiciousTransferEvent data suspicious transfer upload struct
type DataSuspiciousTransferEvent struct {
	Name    string                             `json:"name"`
	T       string                             `json:"type"`
	Reason  string                             `json:"reason"`
	Policy  int                                `json:"policy"`
	Level   int                                `json:"level"`
	Content DataSuspiciousTransferEventContent `json:"content"`
}

// DataSuspiciousTransferEventContent data suspicious transfer upload struct
type DataSuspiciousTransferEventContent struct {
	IllegalIP      string `json:"illegalIP"`
	SrcIP          string `json:"srcIP"`
	DestIP         string `json:"destIP"`
	DestIPLocation string `json:"destIPLocation"`
	UploadByte     int    `json:"uploadByte"`
	During         int    `json:"during"`
}

// cache transfer data
var cdst = cache.New(5*time.Minute, 10*time.Minute)

func dataSuspiciousTransferDetect(info connInfo) {
	uc := getURLConfig().Data.DataSuspiciousTransferDetectConfig

	srcIP := info.sip
	dstIP := info.dip
	origBytes := info.origBytes

	srcIPType := isPrivateIP(srcIP)
	if !srcIPType {
		return
	}

	dstIPType := isPublicIP(dstIP)
	if !dstIPType {
		return
	}

	// 只统计目的ip地址是国外或者国内的
	if uc.ChineseIPaddress == "on" && uc.ForeignIPaddress == "off" {
		IPCountry := getIPCountry(dstIP)
		if IPCountry != "China" || IPCountry == "" {
			return
		}
	}

	if uc.ChineseIPaddress == "off" && uc.ForeignIPaddress == "on" {
		IPCountry := getIPCountry(dstIP)
		if IPCountry == "China" || IPCountry == "" {
			return
		}
	}

	if uc.ChineseIPaddress == "off" && uc.ForeignIPaddress == "off" {
		return
	}

	k := srcIP + "_" + dstIP
	_, err := cdst.IncrementInt(k, origBytes)
	if err != nil {
		cdst.Add(k, origBytes, cache.DefaultExpiration)
	}

}

func dataSuspiciousTransferDetectTicker() {

	go func() {
		uc := getURLConfig()
		if uc.Data.DataSuspiciousTransferDetectSwitch != "on" {
			return
		}

		uConfig := uc.Data.DataSuspiciousTransferDetectConfig
		tickers := time.NewTicker(time.Second * time.Duration(uConfig.TimeWindow))
		for t := range tickers.C {
			uc := getURLConfig()
			uConfig := uc.Data.DataSuspiciousTransferDetectConfig
			data := cdst.Items()
			for k, v := range data {
				uploadByte := v.Object.(int)
				if uploadByte > uConfig.SumByte {
					msgSplit := strings.Split(k, string('_'))
					srcIP := msgSplit[0]
					destIP := msgSplit[1]

					log.Infof("data suspicious transfer: sum of byte(%d) greater than threshold %d, dst: %s, src: %s, at: %s", uploadByte, uConfig.SumByte, destIP, srcIP, t)
					dstdEventUpload(srcIP, destIP, uploadByte, uc)
				}

			}

			cdst.Flush()
		}
	}()
}

func dstdEventUpload(srcIP string, destIP string, uploadByte int, uc URLConfigs) {

	iae := new(DataSuspiciousTransferEventInfo)
	iae.Action = ""
	iae.Location = srcIP
	iae.Timestamp = time.Now().Unix()
	iae.Event.Name = "data-leak"
	iae.Event.T = "bro"
	iae.Event.Reason = uc.Data.DataSuspiciousTransferDetectConfig.Reason
	iae.Event.Policy = 0
	iae.Event.Level = uc.Data.DataSuspiciousTransferDetectConfig.Level
	iae.Event.Content.IllegalIP = destIP
	iae.Event.Content.SrcIP = srcIP
	iae.Event.Content.DestIP = destIP
	iae.Event.Content.UploadByte = uploadByte
	iae.Event.Content.During = uc.Data.DataSuspiciousTransferDetectConfig.TimeWindow

	jsonBody, err := json.Marshal(iae)
	if err != nil {
		log.Error("suspicious domain event upload，json marshal failed:", err)
		return
	}

	httpPost(configs.uploadEventURL, jsonBody)

}

func getIPCountry(ip string) string {
	country := ""

	curDir := getCurrentDirectory()

	db, err := geoip2.Open(curDir + "/GeoLite2-Country.mmdb")
	if err != nil {
		log.Errorln(err)
		return country
	}

	defer db.Close()

	// If you are using strings that may be invalid, check that ip is not nil
	i := net.ParseIP(ip)
	record, err := db.Country(i)
	if err != nil {
		log.Errorln(err)
		return country
	}

	country = record.Country.Names["en"]

	return country
}
