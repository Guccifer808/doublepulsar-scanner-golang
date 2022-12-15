package main

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

var (
	negotiateProtocolRequest, _  = hex.DecodeString("00000085ff534d4272000000001853c00000000000000000000000000000fffe00004000006200025043204e4554574f524b2050524f4752414d20312e3000024c414e4d414e312e30000257696e646f777320666f7220576f726b67726f75707320332e316100024c4d312e325830303200024c414e4d414e322e3100024e54204c4d20302e313200")
	sessionSetupRequest, _       = hex.DecodeString("00000088ff534d4273000000001807c00000000000000000000000000000fffe000040000dff00880004110a000000000000000100000000000000d40000004b000000000000570069006e0064006f007700730020003200300030003000200032003100390035000000570069006e0064006f007700730020003200300030003000200035002e0030000000")
	treeConnectRequest, _        = hex.DecodeString("00000060ff534d4275000000001807c00000000000000000000000000000fffe0008400004ff006000080001003500005c005c003100390032002e003100360038002e003100370035002e003100320038005c00490050004300240000003f3f3f3f3f00")
	transNamedPipeRequest, _     = hex.DecodeString("0000004aff534d42250000000018012800000000000000000000000000088ea3010852981000000000ffffffff0000000000000000000000004a0000004a0002002300000007005c504950455c00")
	trans2SessionSetupRequest, _ = hex.DecodeString("0000004eff534d4232000000001807c00000000000000000000000000008fffe000841000f0c0000000100000000000000a6d9a40000000c00420000004e0001000e000d0000000000000000000000000000")
)

type ScanStatus string

const (
	statusUnknown    = ScanStatus("?")
	statusVulnerable = ScanStatus("+")
	statusBackdored  = ScanStatus("!")
)

type Target struct {
	IP      string
	Netmask string
}

type Result struct {
	Netmask string
	IP      string
	Text    string
	Error   error
	Status  ScanStatus
}

func scanHost(t *Target) *Result {

	res := &Result{IP: t.IP, Netmask: t.Netmask}

	timeout := time.Second * 5
	conn, err := net.DialTimeout("tcp", t.IP+":445", timeout)
	if err != nil {
		res.Error = err
		return res
	}

	conn.SetDeadline(time.Now().Add(time.Second * 10))
	conn.Write(negotiateProtocolRequest)
	reply := make([]byte, 1024)
	if n, err := conn.Read(reply); err != nil || n < 36 {
		res.Error = err
		return res
	}

	if binary.LittleEndian.Uint32(reply[9:13]) != 0 {
		res.Error = err
		return res
	}

	conn.Write(sessionSetupRequest)

	n, err := conn.Read(reply)
	if err != nil || n < 36 {
		res.Error = err
		return res
	}

	if binary.LittleEndian.Uint32(reply[9:13]) != 0 {
		res.Status = statusUnknown
		res.Text = fmt.Sprintf("Can't authorize to SMB. Imposible to check is host vulnerable or not.")
		res.Error = err
		return res
	}

	var os string
	sessionSetupResponse := reply[36:n]
	if wordCount := sessionSetupResponse[0]; wordCount != 0 {
		byteCount := binary.LittleEndian.Uint16(sessionSetupResponse[7:9])
		if n != int(byteCount)+45 {
			fmt.Println("invalid session setup AndX response")
		} else {
			for i := 10; i < len(sessionSetupResponse)-1; i++ {
				if sessionSetupResponse[i] == 0 && sessionSetupResponse[i+1] == 0 {
					os = string(sessionSetupResponse[10:i])
					break
				}
			}
		}

	}
	userID := reply[32:34]
	treeConnectRequest[32] = userID[0]
	treeConnectRequest[33] = userID[1]
	conn.Write(treeConnectRequest)

	if n, err := conn.Read(reply); err != nil || n < 36 {
		res.Error = err
		return res
	}

	treeID := reply[28:30]
	transNamedPipeRequest[28] = treeID[0]
	transNamedPipeRequest[29] = treeID[1]
	transNamedPipeRequest[32] = userID[0]
	transNamedPipeRequest[33] = userID[1]

	conn.Write(transNamedPipeRequest)
	if n, err := conn.Read(reply); err != nil || n < 36 {
		res.Error = err
		return res
	}

	if reply[9] == 0x05 && reply[10] == 0x02 && reply[11] == 0x00 && reply[12] == 0xc0 {
		res.Status = statusVulnerable
		res.Text = fmt.Sprintf("Seems vulnerable for MS17-010. Operation System: %s.", strings.Replace(os, "\x00", "", -1))

		trans2SessionSetupRequest[28] = treeID[0]
		trans2SessionSetupRequest[29] = treeID[1]
		trans2SessionSetupRequest[32] = userID[0]
		trans2SessionSetupRequest[33] = userID[1]

		conn.Write(trans2SessionSetupRequest)

		if n, err := conn.Read(reply); err != nil || n < 36 {
			res.Error = err
			return res
		}

		if reply[34] == 0x51 {
			res.Status = statusBackdored
			res.Text += fmt.Sprintf(" Seems to be infected by DoublePulsar.")
		}

	}

	return res
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func scanner(targets <-chan *Target, results chan<- *Result, verbose bool, wg *sync.WaitGroup) {
	defer wg.Done()

	for t := range targets {
		if verbose {
			fmt.Printf("[] Scanning target: %s\n", t.IP)
		}
		results <- scanHost(t)
	}
}

func reporter(results <-chan *Result, csv *os.File, verbose bool, wg *sync.WaitGroup) {
	defer wg.Done()

	for r := range results {
		if r.Text != "" {
			fmt.Printf("[%s] %s. %s\n", r.Status, r.IP, r.Text)

			csv.Write([]byte(r.Netmask + ";"))
			csv.Write([]byte(r.IP + ";"))
			csv.Write([]byte(fmt.Sprintf("[%s] %s\n", r.Status, r.Text)))
		}
	}
}

func main() {
	fmt.Println("Scanner tool\n")

	host := flag.String("ip", "", "IP address")
	netmask := flag.String("net", "", "IP network address. Example: 10.0.1.0/24")
	workers := flag.Int("workers", 200, "Count of concurrent workers.")
	verbose := flag.Bool("verbose", false, "Verbose output")
	file := flag.String("file", "", "File with list of targets to scan. Each address or netmask on new line.")
	out := flag.String("out", "", "Output file with results of scan in CSV format. Example: results.csv")

	flag.Parse()

	targets := make(chan *Target, 100)
	results := make(chan *Result, 1)

	var wgWorkers sync.WaitGroup

	wgWorkers.Add(*workers)
	for w := 0; w < *workers; w++ {
		go scanner(targets, results, *verbose, &wgWorkers)
	}

	var csv *os.File

	if *out != "" {
		var err error
		csv, err = os.Create(*out)
		if err != nil {
			log.Fatal(err)
		}
		defer csv.Close()
	}

	var wgReporter sync.WaitGroup
	wgReporter.Add(1)
	go reporter(results, csv, *verbose, &wgReporter)

	if *host != "" {
		targets <- &Target{IP: *host}
	}

	if *netmask != "" {
		ip, ipNet, err := net.ParseCIDR(*netmask)
		if err != nil {
			log.Fatal(err)
		}

		for ip := ip.Mask(ipNet.Mask); ipNet.Contains(ip); incIP(ip) {
			targets <- &Target{IP: ip.String(), Netmask: ipNet.String()}
		}
	}

	if *file != "" {
		f, err := os.Open(*file)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()

		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			if net.ParseIP(scanner.Text()) != nil {
				targets <- &Target{IP: scanner.Text()}
			} else {
				ip, ipNet, err := net.ParseCIDR(scanner.Text())
				if err != nil {
					log.Fatal(err)
				}

				for ip := ip.Mask(ipNet.Mask); ipNet.Contains(ip); incIP(ip) {
					targets <- &Target{IP: ip.String(), Netmask: ipNet.String()}
				}
			}
		}
	}

	close(targets)
	wgWorkers.Wait()

	close(results)
	wgReporter.Wait()

}
