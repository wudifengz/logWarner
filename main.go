package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"github.com/color"
	"net"
	"strconv"
	"strings"
	"time"
)

var udpChans = make(chan bool, 5000)

var (
	ErrorIPPort      = errors.New("UDP Server Error: Wrong IP or Port")
	ErrorReadConn    = errors.New("UDP Server Error: Can't Read data from connection")
	ErrorTimeType    = errors.New("error log data: Error Time Type")
	ErrorContentType = errors.New("error log data: Error Content Type")
	ErrorLogFormat   = errors.New("error log data: Error Log Format")
	ErrorSIP         = errors.New("error IP: Error Source IP")
	ErrorDip         = errors.New("error IP: Error Destination IP")
	ErrorLogData     = errors.New("error log data: Unknown Log Data")
	COUNTPERDAY      = 0
	DAYS             = time.Now().Day()
)

func print_c(ss string, colors string) {
	switch colors {
	case "red":
		color.HiRed(ss)
	case "green":
		color.HiGreen(ss)
	case "blue":
		color.HiBlue(ss)
	case "yellow":
		color.HiYellow(ss)
	default:
		fmt.Println(ss)
	}
}
func ParserData(data []byte, local *string) {
	var dp DataParser
	tmpDay := time.Now().Day()
	if tmpDay != DAYS {
		DAYS = tmpDay
		COUNTPERDAY = 1
	}
	c, dataString, e := dp.Parser(data, local)
	if e != nil {
		fmt.Println(e)
	} else {
		if c != "" || dataString != "" {
			fmt.Println(strings.Repeat("-", 40), COUNTPERDAY, strings.Repeat("-", 40))
			print_c(dataString, c)
		}
	}
	COUNTPERDAY += 1
}
func udpProcess(conn *net.UDPConn, local *string) {
	data := make([]byte, 5120)
	n, _, err := conn.ReadFromUDP(data)
	if err != nil {
		panic(ErrorReadConn)
	}
	if !bytes.Equal(data[:9], []byte("check the")) {
		go ParserData(data[:n], local)
		<-udpChans
	}
}

func udpServer(udpaddr string, local *string) {
	udpAddr, err := net.ResolveUDPAddr("udp", udpaddr)
	if err != nil {
		panic(ErrorIPPort)
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	defer conn.Close()
	if err != nil {
		panic(ErrorReadConn)
	}
	for {
		udpChans <- true
		go udpProcess(conn, local)
	}
}

func main() {
	port := flag.Int("p", 514, "Port for listen")
	local := flag.String("l", "随州", "location like 随州 or 鄂州 or else!")
	flag.Parse()
	fmt.Println("Set Port :", *port, "Set Location :", *local, "\nIf you want to change them use -h to sea help.")
	address := "0.0.0.0:" + strconv.Itoa(*port)
	udpServer(address, local)
}
