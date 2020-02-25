package main

import "database/sql"

func httpWorker(httpChan <-chan httpInfo) {
	for i := 0; i < 200; i++ {
		go func() {
			for msg := range httpChan {
				go httpDetect(msg)
			}
		}()
	}
}

func httpDetect(info httpInfo) {
	uc := getURLConfig()
	if uc.Data.DstAddrDetectSwitch == "on" {
		illegalDomainDetect(info)
	}

	if uc.Data.SuspiciousDomainDetectSwitch == "on" {
		suspiciousDomainDetect(info)
	}
}

func connDetect(info connInfo, db *sql.DB) {
	uc := getURLConfig()

	//
	if uc.Data.DataSuspiciousTransferDetectSwitch == "on" {
		dataSuspiciousTransferDetect(info)
	}

	// dst addr detect
	if uc.Data.DstAddrDetectSwitch == "on" {
		illegalAddressDetect(info)
	}

	// scan detect
	if uc.Data.ScanSwitch == "on" {
		scanDetect(info)
	}

	// data leak detect
	if uc.Data.DataLeakDetectSwitch == "on" {
		leakDetect(info, db)
	}

	// syn flood detect
	if uc.Data.SynFloodSwitch == "on" && info.transportLayerProtocol == "tcp" {
		synFloodDetect(info)
	}

	// udp flood detect
	if uc.Data.UDPFloodSwitch == "on" && info.transportLayerProtocol == "udp" {
		udpFloodDetect(info)
	}

}
