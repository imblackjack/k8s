package main

import (
	"fmt"
	"strconv"
	"strings"

	_ "github.com/go-sql-driver/mysql"
)

// get conn info
type connInfo struct {
	time                   string
	duration               float64
	sip                    string
	sport                  int
	dip                    string
	dport                  int
	connState              string
	historyState           string
	origBytes              int
	respBytes              int
	origPkts               int
	respPkts               int
	origIPBytes            int
	respIPBytes            int
	transportLayerProtocol string
	applicationProtocol    string
}

// get software info
type softwareInfo struct {
	ip             string
	port           int
	softwareType   string
	product        string
	productVersion string
}

// get http info
type httpInfo struct {
	time            string
	sip             string
	sport           int
	dip             string
	dport           int
	host            string
	method          string
	uri             string
	referer         string
	userAgent       string
	requestBodyLen  int
	responseBodyLen int
	statusCode      int
	proxied         string
	postBody        string
	responseBody    string
	responseTime    float64
	during          int
}

func formatConnInfo(msg string, topicName string) (connInfo, error) {
	var e error
	var info connInfo

	msgSplit := strings.Split(msg, string('\t'))
	if len(msgSplit) != 21 {
		e := fmt.Errorf("invalid log format, topic name: %s, msg: %s", topicName, msg)
		return info, e
	}

	if msgSplit[3] != "-" && msgSplit[5] != "-" && msgSplit[9] != "-" && msgSplit[10] != "-" && msgSplit[16] != "-" && msgSplit[18] != "-" && msgSplit[17] != "-" && msgSplit[19] != "-" && msgSplit[8] != "-" {

		info.time = msgSplit[0]
		info.sip = msgSplit[2]
		info.sport, e = strconv.Atoi(msgSplit[3])
		info.dip = msgSplit[4]

		info.dport, e = strconv.Atoi(msgSplit[5])

		info.origBytes, e = strconv.Atoi(msgSplit[9])
		info.respBytes, e = strconv.Atoi(msgSplit[10])
		info.connState = msgSplit[11]
		info.historyState = msgSplit[15]
		info.origPkts, e = strconv.Atoi(msgSplit[16])
		info.respPkts, e = strconv.Atoi(msgSplit[18])
		info.origIPBytes, e = strconv.Atoi(msgSplit[17])
		info.respIPBytes, e = strconv.Atoi(msgSplit[19])
		info.transportLayerProtocol = msgSplit[6]
		info.applicationProtocol = msgSplit[7]
		info.duration, e = strconv.ParseFloat(msgSplit[8], 64)

	} else {
		e := fmt.Errorf("conn log parse failed, topic name: %s, msg: %s", topicName, msg)
		return info, e
	}

	return info, e
}

func formatSoftwareInfo(msg string, topicName string) (softwareInfo, error) {
	var e error
	var info softwareInfo

	msgSplit := strings.Split(msg, string('\t'))
	if len(msgSplit) != 11 {
		e := fmt.Errorf("Invalid log format, topic name: %s, msg: %s", topicName, msg)
		return info, e
	}

	info.ip = msgSplit[1]

	port := msgSplit[2]
	if port != "-" {
		p, err := strconv.Atoi(port)
		if err == nil {
			info.port = p
		}
	}

	info.softwareType = msgSplit[3]
	info.product = msgSplit[4]
	info.productVersion = msgSplit[10]

	return info, e
}

func formatHTTPInfo(msg string, topicName string) (httpInfo, error) {
	var e error
	var info httpInfo

	if strings.HasPrefix(msg, "#") {
		e := fmt.Errorf("Invalid log format, topic name: %s, msg: %s", topicName, msg)
		return info, e
	}

	msgSplit := strings.Split(msg, string('\t'))

	if msgSplit[2] != "-" && msgSplit[4] != "-" && msgSplit[10] != "-" && msgSplit[11] != "-" && msgSplit[12] != "-" && msgSplit[17] != "-" {
		info.time = msgSplit[0]
		info.sip = msgSplit[1]
		info.sport, e = strconv.Atoi(msgSplit[2])
		info.dip = msgSplit[3]
		info.dport, e = strconv.Atoi(msgSplit[4])
		info.method = msgSplit[5]
		info.host = msgSplit[6]
		info.uri = msgSplit[7]
		info.referer = msgSplit[8]
		info.userAgent = msgSplit[9]
		info.requestBodyLen, e = strconv.Atoi(msgSplit[10])
		info.responseBodyLen, e = strconv.Atoi(msgSplit[11])
		info.statusCode, e = strconv.Atoi(msgSplit[12])
		info.proxied = msgSplit[13]
		info.postBody = msgSplit[14]
		info.responseBody = msgSplit[15]
		info.responseTime, e = strconv.ParseFloat(msgSplit[16], 64)
	} else {
		e := fmt.Errorf("http log parse failed, topic name: %s, msg: %s", topicName, msg)
		return info, e
	}

	return info, e
}
