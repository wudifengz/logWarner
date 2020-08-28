package main

import (
	"github.com/syslogparser"
	"github.com/syslogparser/rfc3164"
	"github.com/syslogparser/rfc5424"
	"strconv"
	"strings"
	"time"
)

type TZLog struct {
	Times  time.Time
	Sip    string
	Dip    string
	Result string
	Alerts []string
}

func (nt *TZLog) DnameParser(data []byte) {
	logList := strings.Split(string(data), "\" ")
	logMap := map[string]string{}
	for _, v := range logList {
		tmp_str := strings.Split(v, "=\"")
		logMap[tmp_str[0]] = tmp_str[1]
	}
	ti, err := strconv.ParseInt(logMap["time"], 10, 64)
	if err != nil {
		panic(err)
	}
	nt.Times = time.Unix(ti, 0)
	nt.Sip = logMap["addr_src"]
	nt.Dip = logMap["device_ip"]
	nt.Alerts = append(nt.Alerts, logMap["msg_cn"])
}
func (nt *TZLog) oldSkyParser(data []byte, rfcType string) (e error) {
	alertResult := map[string]string{"0": "企图", "1": "成功", "2": "失陷"}
	var ok bool
	var dmp syslogparser.LogParts
	switch rfcType {
	case "RFC_3164":
		{
			p := rfc3164.NewParser(data)
			e = p.Parse()
			if e != nil {
				return
			}
			dmp = p.Dump()
		}
	case "RFC_5424":
		{
			p := rfc5424.NewParser(data)
			e = p.Parse()
			if e != nil {
				return
			}
			dmp = p.Dump()
		}
	}
	nt.Times, ok = dmp["timestamp"].(time.Time)
	if ok == false {
		e = ErrorTimeType
		return
	}
	tmpCont, o := dmp["content"].(string)
	if o == false {
		e = ErrorContentType
		return
	}
	cont := strings.Split(tmpCont, "|!")
	nt.Sip = cont[5]
	nt.Dip = cont[7]
	switch cont[0] {
	case "ips_alert":
		{
			nt.Result = alertResult[cont[23]]
			nt.Alerts = append(nt.Alerts, "网络攻击", nt.Result, cont[2])
		}
	case "webids_alert":
		{
			nt.Result = alertResult[cont[25]]
			nt.Alerts = append(nt.Alerts, "网页漏洞利用", nt.Result, cont[2], cont[15], cont[12])
		}
	case "webshell_alert":
		{
			nt.Result = alertResult[cont[20]]
			nt.Alerts = append(nt.Alerts, "WebShell告警", nt.Result)
		}
	default:
		nt.Alerts = append(nt.Alerts, "威胁情报告警")
	}
	return nil
}
func (nt *TZLog) skyParser(data []byte) {
	result := map[string]string{"0": "企图", "1": "成功", "2": "失陷", "3": "未知"}
	severity := map[string]string{"2": "低危", "4": "中危", "6": "高危", "8": "危急"}
	kill_dic := map[string]string{"0x01000000": "侦察", "0x01010000": "端口扫描", "0x01020000": "信息泄露", "0x01030000": "IP扫描", "0x01040000": "子域名收集", "0x01050000": "网络扫描", "0x02000000": "入侵", "0x02010000": "漏洞探测", "0x02020000": "漏洞利用", "0x02030000": "拒绝服务", "0x02040000": "暴力破解", "0x02050000": "高危操作", "0x02050100": "数据库操作", "0x02050200": "弱口令成功登录", "0x02060000": "网络钓鱼", "0x03000000": "命令控制", "0x03010000": "主机受控", "0x03020000": "黑客工具上传", "0x03030000": "服务器中转行为", "0x03040000": "提权", "0x03050000": "关闭杀毒软件", "0x03060000": "主机信息获取", "0x03070000": "恶意组件下载", "0x03080000": "配置信息上报", "0x03090000": "混合功能控制", "0x030a0000": "命令控制服务器连接", "0x04000000": "横向渗透", "0x04010000": "内网侦察", "0x04020000": "嗅探攻击", "0x04030000": "内网漏洞探测", "0x04040000": "内网漏洞利用", "0x05000000": "数据外泄", "0x05010000": "文件下载", "0x05020000": "拖库行为", "0x05030000": "数据服务器连接", "0x06000000": "痕迹清理", "0x06010000": "后门删除", "0x06020000": "关闭攻击服务", "0x06030000": "清除日志"}
	loglist := strings.Split(strings.Replace(string(data), "<30>skyeye_", "skyeye_", -1), "\" ")
	tmplist := strings.Split(loglist[0], " ")
	logType := tmplist[0]
	loglist[0] = tmplist[1]
	logMap := map[string]string{}
	for _, v := range loglist {
		tmp_str := strings.Split(v, "\"=")
		logMap[tmp_str[0]] = tmp_str[1]
	}
	dateString, ok := logMap["write_date"]
	if ok {
		ti, err := strconv.ParseInt(dateString, 10, 64)
		if err != nil {
			panic(err)
		}
		nt.Times = time.Unix(ti, 0)
	} else {
		date, ok := logMap["access_time"]
		if ok {
			t, e := time.Parse("2006-01-02 15:04:05", date[0:19])
			if e != nil {
				panic(e)
			}
			nt.Times = t
		} else {
			panic("Error time!")
		}
	}
	switch logType {
	case "skyeye_ids":
		{
			nt.Sip = logMap["sip"]
			nt.Dip = logMap["dip"]
			nt.Result = result[logMap["attack_result"]]
			nt.Alerts = append(nt.Alerts, nt.Result, kill_dic[logMap["kill_chain"]], logMap["rule_name"])
		}
	case "skyeye_webattack":
		{
			nt.Sip = logMap["sip"]
			nt.Dip = logMap["dip"]
			nt.Result = result[logMap["attack_result"]]
			nt.Alerts = append(nt.Alerts, nt.Result, logMap["attack_type"], kill_dic[logMap["kill_chain"]], severity[logMap["severity"]], logMap["method"], logMap["site_app"]+"://"+logMap["host"]+logMap["uri"], logMap["weak_passwd"])
		}
	case "skyeye_login":
		{
			nt.Sip = logMap["sip"]
			nt.Dip = logMap["dip"]
			nt.Alerts = append(nt.Alerts, logMap["proto"], logMap["db_ype"], logMap["user"])
		}
	default:
		{
			nt.Times = time.Now()
			nt.Sip = "None"
			nt.Dip = "None"
			for k, v := range logMap {
				nt.Alerts = append(nt.Alerts, k+":"+v)
			}
		}
	}
}

func (nt *TZLog) Parser(data []byte) (e error) {
	var rfc syslogparser.RFC
	switch string(data)[0:7] {
	case "dname=\"":
		nt.DnameParser(data)
		e = nil
	case "<30>sky":
		nt.skyParser(data)
		e = nil
	default:
		rfc, e = syslogparser.DetectRFC(data)
		if e != nil {
			return
		}
		switch rfc {
		case syslogparser.RFC_3164:
			e = nt.oldSkyParser(data, "RFC_3164")
		case syslogparser.RFC_5424:
			e = nt.oldSkyParser(data, "RFC_5424")
		default:
			e = ErrorLogData
		}
	}
	return
}
