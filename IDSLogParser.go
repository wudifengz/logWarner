package main

import (
	"encoding/json"
	"github.com/syslogparser"
	"github.com/syslogparser/rfc3164"
	"github.com/syslogparser/rfc5424"
	"time"
)

type IDSLogContent struct {
	Sour  map[string]interface{} `json:"source"`
	Dest  map[string]interface{} `json:"destination"`
	Proto string                 `json:"protocol"`
	Subj  string                 `json:"subject"`
}
type IDSLog struct {
	Times      time.Time
	LogContent IDSLogContent
}

func (il *IDSLog) Parser(data []byte) (e error) {
	rfc, e := syslogparser.DetectRFC(data)
	if e != nil {
		return
	}
	var ok bool
	var dmp syslogparser.LogParts
	switch rfc {
	case syslogparser.RFC_UNKNOWN:
		e = ErrorLogFormat
		return
	case syslogparser.RFC_3164:
		p := rfc3164.NewParser(data)
		e = p.Parse()
		if e != nil {
			return
		}
		dmp = p.Dump()
	case syslogparser.RFC_5424:
		p := rfc5424.NewParser(data)
		e = p.Parse()
		if e != nil {
			return
		}
		dmp = p.Dump()
	}
	il.Times, ok = dmp["timestamp"].(time.Time)
	if ok == false {
		e = ErrorTimeType
		return
	}
	cont, ok := dmp["content"].(string)
	if ok == false {
		e = ErrorContentType
		return
	}
	_ = json.Unmarshal([]byte(cont), &il.LogContent)
	return nil
}
