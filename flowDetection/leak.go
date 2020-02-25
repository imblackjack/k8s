package main

import (
	"database/sql"
	"encoding/json"
	"time"

	log "github.com/Sirupsen/logrus"
)

type Event struct {
	Name    string                 `json:"name"`
	T       string                 `json:"type"`
	Reason  string                 `json:"reason"`
	Policy  int                    `json:"policy"`
	Level   int                    `json:"level"`
	Content map[string]interface{} `json:"content"`
}

type EventInfo struct {
	Timestamp int64  `json:"timestamp"`
	Location  string `json:"location"`
	Action    string `json:"action"`
	Event     Event  `json:"event"`
}

/*
#fields human_time  uid id.orig_h   id.orig_p   id.resp_h   id.resp_p   proto   service duration    orig_bytes  resp_bytes  conn_state  local_orig  local_resp  missed_bytes    history orig_pkts   orig_ip_bytes   resp_pkts   resp_ip_bytes   tunnel_parents
#types  string  string  addr    port    addr    port    enum    string  interval    count   count   string  bool    bool    count   string  count   count   count   count   set[string]
https://docs.zeek.org/en/stable/scripts/base/protocols/conn/main.bro.html#type-Conn::Info
CREATE TABLE `CORE_SERVICE_RELATED_IP` (
  `ip` varchar(64) NOT NULL,
  `created_at` date DEFAULT NULL,
  PRIMARY KEY (`ip`),
  KEY `created_at` (`created_at`)
)
*/

func leakDetect(info connInfo, db *sql.DB) {
	uc := getURLConfig().Data.DataLeakDetectConfig

	var p *string
	var x string
	switch err := db.QueryRow("select ip from ASSET_OVERVIEW where ip in (?) limit 1", info.dip).Scan(&x); err {
	case sql.ErrNoRows:
		return
	case nil:
		p = &info.dip
	default:
		log.Errorf("db error, %s", err)
		return
	}

	var d sql.NullInt64
	err := db.QueryRow("select max(created_at) - min(created_at) from CORE_SERVICE_RELATED_IP").Scan(&d)
	if err != nil {
		log.Errorf("db error, %s", err)
		return
	}
	if !d.Valid || d.Int64 < uc.StoreDays {
		var e int
		switch err := db.QueryRow("select 1 from ASSET_OVERVIEW where ip = ?", *p).Scan(&e); err {
		case sql.ErrNoRows:
			log.Infof("Add new core service related ip: %s, <-> %s", *p, x)
		case nil:
			log.Infof("Ignore kernel service ip: %s", *p)
			return
		default:
			log.Errorf("db error, %s", err)
			return
		}

		stmt, err := db.Prepare("insert into CORE_SERVICE_RELATED_IP(ip, created_at) values(?, curdate()) on duplicate key update ip = ip")
		if err != nil {
			log.Errorf("db error: %s", err)
			return
		}
		defer stmt.Close()
		_, err = stmt.Exec(*p)
		if err != nil {
			log.Errorf("db error, %s", err)
			return
		}
	} else {
		var product string
		switch err := db.QueryRow("select 1 from ASSET_OVERVIEW where ip = ? and not exists(select 1 from CORE_SERVICE_RELATED_IP where ip = ? limit 1) limit 1", *p, *p).Scan(&product); err {
		case sql.ErrNoRows:
			k := info.sip + "_" + info.dip
			_, found := csd.Get(k)
			if found {
				return
			}

			csd.Set(k, 1, time.Second*time.Duration(uc.TimeWindow))
			log.Infof("data leak: core service is accessed record %d day, suspicous ip found: %s, dst: %s, src: %s", uc.StoreDays, *p, info.dip, info.sip)

			var product string
			db.QueryRow("select product from ASSET_OVERVIEW where ip in (?, ?) limit 1", info.sip, info.dip).Scan(&product)
			e := EventInfo{
				Timestamp: time.Now().Unix(),
				Location:  *p,
				Event: Event{
					Name:   "data-leak",
					T:      "bro",
					Reason: uc.Reason,
					Level:  uc.Level,
					Content: map[string]interface{}{
						"illegalIP": info.sip,
						"srcIP":     info.sip,
						"destIP":    info.dip,
						"service":   product,
						"during":    uc.TimeWindow,
					},
				},
			}
			body, err := json.Marshal(&e)
			if err != nil {
				log.Errorf("json marshal failed: %s", err)
				return
			}
			log.Errorf("body: %s", body)

			httpPost(configs.uploadEventURL, body)
		case nil:
		default:
			log.Errorf("db error %s", err)
		}
	}
}
