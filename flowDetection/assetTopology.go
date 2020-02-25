package main

import (
	"database/sql"

	log "github.com/Sirupsen/logrus"

	_ "github.com/go-sql-driver/mysql"
)

func storeConnInfo(info connInfo, db *sql.DB) {
	stmt, err := db.Prepare("INSERT INTO ASSET_TOPOLOGY (sip, dip, dport, orig_pkts, resp_pkts, orig_ip_bytes, resp_ip_bytes, trans_layer_pro, app_pro) VALUES (?,?,?,?,?,?,?,?,?) on duplicate key update orig_pkts=orig_pkts+?,resp_pkts=resp_pkts+?,orig_ip_bytes=orig_ip_bytes+?,resp_ip_bytes=resp_ip_bytes+?")
	if err != nil {
		log.Errorf("mysql prepare error, %s", err)
	}

	defer stmt.Close()

	_, err = stmt.Exec(info.sip, info.dip, info.dport, info.origPkts, info.respPkts, info.origIPBytes, info.respIPBytes, info.transportLayerProtocol, info.applicationProtocol, info.origPkts, info.respPkts, info.origIPBytes, info.respIPBytes)
	if err != nil {
		log.Errorf("mysql cmd exec error, %s", err)
	}

}

func storeSoftwareInfo(info softwareInfo, db *sql.DB) {
	stmt, err := db.Prepare("INSERT INTO ASSET_PRODUCT (ip, port, software_type, product, product_and_version) VALUES (?,?,?,?,?) on duplicate key update last_modify_time=values(last_modify_time)")
	if err != nil {
		log.Errorf("mysql prepare error, %s", err)
	}

	defer stmt.Close()

	_, err = stmt.Exec(info.ip, info.port, info.softwareType, info.product, info.productVersion)
	if err != nil {
		log.Errorf("mysql cmd exec error, %s", err)
	}

}
