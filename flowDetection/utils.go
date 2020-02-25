package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	log "github.com/Sirupsen/logrus"
	"github.com/jpillora/go-tld"
	"github.com/patrickmn/go-cache"
)

// KV struct in map
type KV struct {
	key   string
	value int
}

func statAndCreateDir(dir string) {
	if _, err := os.Stat(dir); err != nil {
		err := os.MkdirAll(dir, 0755)

		if err != nil {
			log.Fatal("directory create failed: ", dir)
		}
	}
}

func httpGet(url string) ([]byte, error) {
	var err error
	res, err := http.Get(url)
	if err != nil {
		err := fmt.Errorf("http get failed，url: %s，err: %s", url, err)
		return nil, err
	}

	defer res.Body.Close()

	if res.StatusCode != 200 {
		err := fmt.Errorf("response status code error，url: %s, status: %s", url, res.Status)
		return nil, err
	}

	body, _ := ioutil.ReadAll(res.Body)

	return body, err
}

func httpPost(url string, b []byte) {
	body := bytes.NewBuffer([]byte(b))
	res, err := http.Post(url, "application/json;charset=utf-8", body)
	if err != nil {
		log.Error("http post failed:", err)
		return
	}

	_, err = ioutil.ReadAll(res.Body)
	if err != nil {
		log.Error("http post read response failed:", err)
		return
	}

	defer res.Body.Close()

}

func increment(c *cache.Cache, m *sync.RWMutex, k string, n int64) error {
	ok := c.Increment(k, n)
	if ok != nil {
		m.Lock()
		c.Add(k, 1, cache.DefaultExpiration)
		m.Unlock()
	}

	return nil
}

func inStringSlice(s []string, str string) bool {
	for _, v := range s {
		if str == v {
			return true
		}
	}

	return false
}

func setSlice(c *cache.Cache, m *sync.RWMutex, k string, currentValue string) {
	m.Lock()
	v, f := c.Get(k)
	if !f {
		srcSlice := []string{currentValue}
		srcSlice = append(srcSlice, currentValue)
		c.Set(k, srcSlice, cache.DefaultExpiration)
	} else {
		v = append(v.([]string), currentValue)
		c.Set(k, v, cache.DefaultExpiration)
	}
	m.Unlock()
}

func setMap(c *cache.Cache, m *sync.RWMutex, k string, mapKey string) {
	m.Lock()
	v, f := c.Get(k)

	if !f {
		tmpMap := map[string]int{
			mapKey: 1,
		}
		c.Set(k, tmpMap, cache.DefaultExpiration)
	} else {
		cValue := v.(map[string]int)
		mapValue, ok := cValue[mapKey]
		if !ok {
			cValue[mapKey] = 1
		} else {
			cValue[mapKey] = mapValue + 1
		}

		c.Set(k, cValue, cache.DefaultExpiration)
	}
	m.Unlock()
}

func sortByMapValue(m map[string]int) []KV {
	var mapSlice []KV
	for k, v := range m {
		mapSlice = append(mapSlice, KV{k, v})
	}

	sort.Slice(mapSlice, func(i, j int) bool {
		return mapSlice[i].value > mapSlice[j].value // 降序
		// return ss[i].Value > ss[j].Value  // 升序
	})

	return mapSlice
}

func getSrcInfo(k string, c *cache.Cache) string {
	var srcInfo string
	v, f := c.Get(k)
	if f {
		mapSlice := sortByMapValue(v.(map[string]int))
		element := mapSlice[0]
		srcInfo = element.key
	}

	return srcInfo
}

func isPublicIP(ip string) bool {
	IP := net.ParseIP(ip)

	if IP.IsLoopback() || IP.IsLinkLocalMulticast() || IP.IsLinkLocalUnicast() {
		return false
	}
	if ip4 := IP.To4(); ip4 != nil {
		switch true {
		case ip4[0] == 10:
			return false
		case ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31:
			return false
		case ip4[0] == 192 && ip4[1] == 168:
			return false
		default:
			return true
		}
	}

	return false
}

func isPrivateIP(ip string) bool {
	IP := net.ParseIP(ip)

	if IP.IsLoopback() || IP.IsLinkLocalMulticast() || IP.IsLinkLocalUnicast() {
		return false
	}
	if ip4 := IP.To4(); ip4 != nil {
		switch true {
		case ip4[0] == 10:
			return true
		case ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31:
			return true
		case ip4[0] == 192 && ip4[1] == 168:
			return true
		default:
			return false
		}
	}

	return false
}

func tldQuery(url string) string {

	domain := ""

	defer func() {
		if err := recover(); err != nil {
			log.Error(err)
		}
	}()

	u, _ := tld.Parse(url)
	// 解析出错之后，变量u为nil，直接return
	if u == nil {
		return domain
	}

	domain = u.Domain + "." + u.TLD

	return domain
}

func getCurrentDirectory() string {
	dir, err := filepath.Abs(filepath.Dir(os.Args[0])) //返回绝对路径  filepath.Dir(os.Args[0])去除最后一个元素的路径
	if err != nil {
		log.Fatal(err)
	}
	return strings.Replace(dir, "\\", "/", -1) //将\替换成/
}
