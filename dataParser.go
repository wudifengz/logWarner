package main

import (
	"golang.org/x/text/encoding/simplifiedchinese"
	"strings"
)

type DataParser struct {
}

func isGBK(data []byte) bool {
	length := len(data)
	var i int = 0
	for i < length-1 {
		if data[i] <= 0x7f {
			//编码0~127,只有一个字节的编码，兼容ASCII码
			i++
			continue
		} else {
			//大于127的使用双字节编码，落在gbk编码范围内的字符
			if data[i] >= 0x81 &&
				data[i] <= 0xfe &&
				data[i+1] >= 0x40 &&
				data[i+1] <= 0xfe &&
				data[i+1] != 0xf7 {
				i += 2
				continue
			} else {
				return false
			}
		}
	}
	return true
}

func isUtf8(data []byte) bool {
	i := 0
	for j := 0; j <= len(data); j++ {
		if i == 0 {
			if (data[i] & 0x80) != 0 {
				for (data[i] & 0x80) != 0 {
					data[i] <<= 1
					i++
				}
				if i < 2 || i > 6 {
					return false
				}
				i--
			}
		} else {
			if data[i]&0xc0 != 0x80 {
				return false
			}
			i--
		}
	}
	return i == 0
}
func Decode(bdata []byte) (dataType int, data []byte) {
	if isGBK(bdata) == true {
		data, _ = simplifiedchinese.GBK.NewDecoder().Bytes(bdata)
		dataType = 1
	} else if isUtf8(bdata) == true {
		dataType = 2
		data = bdata
	}
	return
}
func (dp *DataParser) Parser(bdata []byte, local *string) (color, logString string, e error) {
	dataType, dataString := Decode(bdata)
	if string(dataString)[:8] == "check the" {
		return "", "", nil
	}
	e = nil
	var ipck IPChecker
	ipck.init()
	if dataType == 1 {
		var idslog IDSLog
		e = idslog.Parser(dataString)
		if e != nil {
			return "", "", e
		}
		sip, ok := idslog.LogContent.Sour["ip"].(string)
		if ok == false {
			e = ErrorSIP
			return "", "", e
		}
		dip, ok := idslog.LogContent.Dest["ip"].(string)
		if ok == false {
			e = ErrorDip
			return "", "", e
		}
		sipd := ipck.checkIP(sip)
		dipd := ipck.checkIP(dip)
		if sipd == *local {
			color = "normal"
		} else if sipd != "省外" && dipd != "省外" {
			color = "yellow"
		} else {
			color = "red"
		}
		a := strings.Join([]string{"From :", sip, "(", sipd, ")", " - > To :", dip, "(", dipd, ")"}, "")
		logString = strings.Join([]string{"qm-IDS", idslog.Times.Format("2006-01-02 03:04:05"), a, idslog.LogContent.Proto, idslog.LogContent.Subj}, " - ")
	} else if dataType == 2 {
		var tzlog TZLog
		e = tzlog.Parser(dataString)
		if e != nil {
			return "", "", e
		}
		sipd := ipck.checkIP(tzlog.Sip)
		dipd := ipck.checkIP(tzlog.Dip)
		if tzlog.Result == "成功" || tzlog.Result == "失陷" {
			color = "red"
		} else {

			if sipd == *local {
				color = "normal"
			} else if sipd != "省外" && dipd != "省外" {
				color = "yellow"
			} else {
				color = "red"
			}
		}
		a := strings.Join([]string{"From :", tzlog.Sip, "(", sipd, ")", " - > To :", tzlog.Dip, "(", dipd, ")"}, "")
		logString = strings.Join([]string{"skyeye_TZ", tzlog.Times.Format("2006-01-02 03:04:05"), a, strings.Join(tzlog.Alerts, " , ")}, " - ")
	}
	return
}
