package main

import (
	"database/sql"
	"flag"
	"path"
	"strings"
	"time"

	log "github.com/Sirupsen/logrus"
	rotatelogs "github.com/lestrrat/go-file-rotatelogs"

	"github.com/confluentinc/confluent-kafka-go/kafka"
	_ "github.com/go-sql-driver/mysql"
)

var (
	configFile = flag.String("c", "config.ini", "config file")
)

func main() {
	// init config
	flag.Parse()
	configs := configParse(*configFile)

	// init log
	logDir, _ := path.Split(configs.LogFile)
	statAndCreateDir(logDir)
	writer, _ := rotatelogs.New(
		configs.LogFile+".%Y%m%d%H%M",
		rotatelogs.WithLinkName(configs.LogFile),
		rotatelogs.WithMaxAge(time.Duration(604800)*time.Second),
		rotatelogs.WithRotationTime(time.Duration(86400)*time.Second),
	)
	log.SetOutput(writer)
	log.SetLevel(log.DebugLevel)

	log.Debugln(configs)

	// init mysql
	dataSource := configs.mysqlUser + ":" + configs.mysqlPassword + "@tcp(" + configs.mysqlAddr + ":" + configs.mysqlPort + ")/" + configs.mysqlDatabase
	db, err := sql.Open("mysql", dataSource)
	if err != nil {
		panic(err)
	}

	// init url config
	err = loadURLConfig()
	if err != nil {
		log.Errorln(err)
	}

	// reload url config
	go reloadURLConfig()

	// init broker
	c, err := kafka.NewConsumer(&kafka.ConfigMap{
		"bootstrap.servers":        configs.kafkaBrokers,
		"group.id":                 configs.consumerGroupName,
		"auto.offset.reset":        "latest",
		"request.timeout.ms":       "90000",
		"session.timeout.ms":       "60000",
		"socket.timeout.ms":        "90000",
		"fetch.wait.max.ms":        "60000",
		"enable.auto.commit":       false,
		"enable.auto.offset.store": false,
	})
	if err != nil {
		panic(err)
	}

	// ticker
	floodDetectTicker()
	scanTicker()
	dataSuspiciousTransferDetectTicker()

	// http chan
	var httpChan = make(chan httpInfo, 5000)
	// http worker
	httpWorker(httpChan)

	uc := getURLConfig()
	c.SubscribeTopics([]string{configs.kafkaConnTopic, configs.kafkaSoftwareTopic, configs.kafkaHTTPTopic}, nil)
	for {
		msg, err := c.ReadMessage(-1)
		if err == nil {
			if strings.HasPrefix(msg.TopicPartition.String(), configs.kafkaConnTopic) {
				info, err := formatConnInfo(string(msg.Value), msg.TopicPartition.String())
				if err != nil {
					continue
				}

				if uc.Data.AssetDetectionSwitch == "on" {
					storeConnInfo(info, db)
				}
				connDetect(info, db)
			} else if strings.HasPrefix(msg.TopicPartition.String(), configs.kafkaSoftwareTopic) {
				info, err := formatSoftwareInfo(string(msg.Value), msg.TopicPartition.String())
				if err != nil {
					log.Warnln(err, "msg:", string(msg.Value))
					continue
				}

				if uc.Data.AssetDetectionSwitch == "on" {
					storeSoftwareInfo(info, db)
				}
			} else if strings.HasPrefix(msg.TopicPartition.String(), configs.kafkaHTTPTopic) {
				info, err := formatHTTPInfo(string(msg.Value), msg.TopicPartition.String())
				if err != nil {
					log.Warnln(err, "msg:", string(msg.Value))
					continue
				}

				httpChan <- info
			}
		} else {
			// The client will automatically try to recover from all errors.
			log.Errorf("Consumer error, %s", err)
		}
	}

	//

	defer c.Close()
	defer db.Close()
}
