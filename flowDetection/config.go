package main

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/go-ini/ini"
)

// Configs is assets topology config
type Configs struct {
	LogFile            string
	mysqlUser          string
	mysqlPassword      string
	mysqlAddr          string
	mysqlPort          string
	mysqlDatabase      string
	kafkaBrokers       string
	kafkaConnTopic     string
	kafkaSoftwareTopic string
	kafkaHTTPTopic     string
	consumerGroupName  string
	configURL          string
	uploadEventURL     string
}

// URLConfigs url config
type URLConfigs struct {
	Data Data `json:"data"`
}

// Data url config
type Data struct {
	AssetDetectionSwitch               string                           `json:"AssetDetectionSwitch"`
	SynFloodSwitch                     string                           `json:"synFloodSwitch"`
	UDPFloodSwitch                     string                           `json:"udpFloodSwitch"`
	SynFloodConfig                     SynFloodItem                     `json:"synFloodConfig"`
	UDPFloodConfig                     UDPFloodItem                     `json:"udpFloodConfig"`
	ScanSwitch                         string                           `json:"scanSwitch"`
	DstAddrDetectSwitch                string                           `json:"dstAddrDetectSwitch"`
	ScanConfig                         ScanItem                         `json:"scanConfig"`
	DstAddrDetectConfig                DstAddrDetectItem                `json:"dstAddrDetectConfig"`
	SuspiciousDomainDetectSwitch       string                           `json:"SuspiciousDomainDetectSwitch"`
	DataSuspiciousTransferDetectSwitch string                           `json:"dataSuspiciousTransferDetectSwitch"`
	SuspiciousDomainDetectConfig       SuspiciousDomainDetectItem       `json:"suspiciousDomainDetectConfig"`
	DataSuspiciousTransferDetectConfig DataSuspiciousTransferDetectItem `json:"dataSuspiciousTransferDetectConfig"`
	DataLeakDetectSwitch               string                           `json:"dataLeakDetectSwitch"`
	DataLeakDetectConfig               struct {
		TimeWindow int    `json:"timeWindow"`
		Level      int    `json:"level"`
		Reason     string `json:"reason"`
		StoreDays  int64  `json:"storeDays"`
	} `json:"dataLeakDetectConfig"`
}

// SynFloodItem url config
type SynFloodItem struct {
	SynCount               int     `json:"synCount"`
	SynAttampCount         int     `json:"synAttampCount"`
	SynAckCountDivSynCount float32 `json:"synAckCountDivsynCount"`
	SynRcvdCount           int     `json:"synRcvdCount"`
	Level                  int     `json:"level"`
	Reason                 string  `json:"reason"`
	TimeWindow             int     `json:"timeWindow"`
}

// UDPFloodItem url config
type UDPFloodItem struct {
	UDPCount   int    `json:"udpCount"`
	Level      int    `json:"level"`
	Reason     string `json:"reason"`
	TimeWindow int    `json:"timeWindow"`
}

// ScanItem url config
type ScanItem struct {
	DstAddrCount int    `json:"dstAddrCount"`
	Level        int    `json:"level"`
	Reason       string `json:"reason"`
	TimeWindow   int    `json:"timeWindow"`
}

// DstAddrDetectItem url config
type DstAddrDetectItem struct {
	BlackList  []string `json:"blackList"`
	WhiteList  []string `json:"whiteList"`
	Level      int      `json:"level"`
	Reason     string   `json:"reason"`
	TimeWindow int      `json:"timeWindow"`
}

// SuspiciousDomainDetectItem url config
type SuspiciousDomainDetectItem struct {
	AlreadyRegisteredDays int64    `json:"alreadyRegisteredDays"`
	StaticFilter          []string `json:"staticFilter"`
	Level                 int      `json:"level"`
	Reason                string   `json:"reason"`
	TimeWindow            int      `json:"timeWindow"`
}

// DataSuspiciousTransferDetectItem url config
type DataSuspiciousTransferDetectItem struct {
	SumByte          int    `json:"sumByte"`
	ForeignIPaddress string `json:"foreignIPaddress"`
	ChineseIPaddress string `json:"chineseIPaddress"`
	Level            int    `json:"level"`
	Reason           string `json:"reason"`
	TimeWindow       int    `json:"timeWindow"`
}

var configs Configs
var urlConfigs URLConfigs
var urlConfigLock = new(sync.RWMutex)

func configParse(configFile string) Configs {
	configIni, err := ini.Load(configFile)

	if err != nil {
		log.Fatal("config parse failed: ", err)
	} else {
		configs.LogFile = configIni.Section("main").Key("logFile").String()
		if len(configs.LogFile) == 0 {
			configs.LogFile = "/data0/logs/flowDetection.log"
		}

		configs.mysqlUser = configIni.Section("main").Key("mysqlUser").String()
		if len(configs.mysqlUser) == 0 {
			log.Fatal("mysql user not config")
		}

		configs.mysqlPassword = configIni.Section("main").Key("mysqlPassword").String()
		if len(configs.mysqlPassword) == 0 {
			log.Fatal("mysql password not config")
		}

		configs.mysqlAddr = configIni.Section("main").Key("mysqlAddr").String()
		if len(configs.mysqlAddr) == 0 {
			log.Fatal("mysqlAddr not config")
		}

		configs.mysqlPort = configIni.Section("main").Key("mysqlPort").String()
		if len(configs.mysqlPort) == 0 {
			log.Fatal("mysqlPort not config")
		}

		configs.mysqlDatabase = configIni.Section("main").Key("mysqlDatabase").String()
		if len(configs.mysqlDatabase) == 0 {
			log.Fatal("mysqlDatabase not config")
		}

		configs.kafkaBrokers = configIni.Section("main").Key("kafkaBrokers").String()
		if len(configs.kafkaBrokers) == 0 {
			log.Fatal("kafkaBrokers not config")
		}

		configs.kafkaConnTopic = configIni.Section("main").Key("kafkaConnTopic").String()
		if len(configs.kafkaConnTopic) == 0 {
			log.Fatal("kafkaConnTopic not config")
		}

		configs.kafkaSoftwareTopic = configIni.Section("main").Key("kafkaSoftwareTopic").String()
		if len(configs.kafkaSoftwareTopic) == 0 {
			log.Fatal("kafkaSoftwareTopic not config")
		}

		configs.kafkaHTTPTopic = configIni.Section("main").Key("kafkaHttpTopic").String()
		if len(configs.kafkaHTTPTopic) == 0 {
			log.Fatal("kafkaHttpTopic not config")
		}

		configs.consumerGroupName = configIni.Section("main").Key("consumerGroupName").String()
		if len(configs.consumerGroupName) == 0 {
			log.Fatal("consumerGroupName not config")
		}

		configs.configURL = configIni.Section("main").Key("configURL").String()
		if len(configs.configURL) == 0 {
			log.Fatal("configURL not config")
		}

		configs.uploadEventURL = configIni.Section("main").Key("uploadEventURL").String()
		if len(configs.uploadEventURL) == 0 {
			log.Fatal("uploadEventURL not config")
		}

	}

	return configs
}

func loadURLConfig() error {

	resBody, err := httpGet(configs.configURL)
	if err != nil {
		err := fmt.Errorf("get url config failed: %s", err)
		return err
	}

	// write lock
	urlConfigLock.Lock()
	lastURLConfigs := urlConfigs
	err = json.Unmarshal(resBody, &urlConfigs)
	if err != nil {
		err := fmt.Errorf("unmarshal url config failed: %s", err)
		urlConfigs = lastURLConfigs
		urlConfigLock.Unlock()
		return err
	}

	urlConfigLock.Unlock()
	return nil
}

func reloadURLConfig() {
	// timer
	ticker := time.NewTicker(time.Second * 2)
	for range ticker.C {
		func() {
			err := loadURLConfig()
			if err != nil {
				log.Errorln("reload url config,", err)
			}

		}()
	}
}

func getURLConfig() URLConfigs {
	urlConfigLock.RLock()
	defer urlConfigLock.RUnlock()
	return urlConfigs
}
