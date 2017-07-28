package util

import (
	"fmt"
	"strconv"
	"strings"
)

type Cidr struct {
	Cidr      string
	Begin     string
	BeginNo   int64
	End       string
	EndNo     int64
	IpCount   int64
	Mask      string
	MaskCount int    //  /22
	IpNoList  []int  //[221, 15, 23, 10]
	CidrBin   string //cidr Ip转换成二进制
}

func NewCidr(cidrStr string) *Cidr {
	if !strings.Contains(cidrStr, "/") {
		cidrStr = cidrStr + "/32"
	}
	tmpList := strings.Split(cidrStr, "/")
	maskCountStr := tmpList[1]
	ip := tmpList[0]
	mastCount, _ := strconv.Atoi(maskCountStr)
	var cidrPtr *Cidr = new(Cidr)
	cidrPtr.Cidr = cidrStr
	cidrPtr.MaskCount = mastCount
	ipNoStrList := strings.Split(ip, ".")
	cidrPtr.IpNoList = make([]int, 0, 4)
	for _, ipNoStr := range ipNoStrList {
		ipNo, _ := strconv.Atoi(ipNoStr)
		cidrPtr.IpNoList = append(cidrPtr.IpNoList, ipNo)
		bin := strconv.FormatInt(int64(ipNo), 2)
		if len(bin) < 8 {
			rest := 8 - len(bin)
			fillZero := ""
			for i := 0; i < rest; i++ {
				fillZero += "0"
			}
			bin = fillZero + bin
		}
		cidrPtr.CidrBin += bin
	}
	return cidrPtr
}

func (cidrPtr *Cidr) Dump() {
	fmt.Printf("cidr:%s\n", cidrPtr.Cidr)
	fmt.Printf("begin:%s, end:%s\n", cidrPtr.Begin, cidrPtr.End)
	fmt.Printf("beginNo:%d, endNo:%d\n", cidrPtr.BeginNo, cidrPtr.EndNo)
	fmt.Printf("IpCount:%d\n", cidrPtr.IpCount)
	fmt.Printf("Mask:%s\n", cidrPtr.Mask)
	fmt.Printf("MaskCount:%d\n", cidrPtr.MaskCount)
	fmt.Printf("CidrBin:%s\n", cidrPtr.CidrBin)
}

func (cidrPtr *Cidr) GetMask() string {
	var mask string = ""
	for i := 0; i < cidrPtr.MaskCount; i++ {
		mask = mask + "1"
	}
	for i := 0; i < (32 - cidrPtr.MaskCount); i++ {
		mask = mask + "0"
	}
	return mask
}

func (cidrPtr *Cidr) GetBeginEndIp() *Cidr {
	maskBin, _ := strconv.ParseInt(cidrPtr.Mask, 2, 64)
	cidrBin, _ := strconv.ParseInt(cidrPtr.CidrBin, 2, 64)
	andBin := maskBin & cidrBin
	andStr := strconv.FormatInt(andBin, 2)
	if len(andStr) < 32 {
		diff := 32 - len(andStr)
		fillZero := ""
		for i := 0; i < diff; i++ {
			fillZero += "0"
		}
		andStr = fillZero + andStr
	}
	rest := 32 - cidrPtr.MaskCount
	left := andStr[0:cidrPtr.MaskCount]
	right := ""
	for i := 0; i < rest; i++ {
		if i == rest-1 {
			right += "0"
		} else {
			right += "1"
		}

	}
	end := left + right
	part1 := end[0:8]
	part2 := end[8:16]
	part3 := end[16:24]
	part4 := end[24:32]
	part1Int, _ := strconv.ParseInt(part1, 2, 64)
	part2Int, _ := strconv.ParseInt(part2, 2, 64)
	part3Int, _ := strconv.ParseInt(part3, 2, 64)
	part4Int, _ := strconv.ParseInt(part4, 2, 64)
	cidrPtr.End = strconv.FormatInt(part1Int, 10) + "." +
		strconv.FormatInt(part2Int, 10) + "." +
		strconv.FormatInt(part3Int, 10) + "." +
		strconv.FormatInt(part4Int, 10)
	cidrPtr.EndNo, _ = strconv.ParseInt(end, 2, 64)
	right = ""
	for i := 0; i < rest; i++ {
		if i == rest-1 {
			right += "1"
		} else {
			right += "0"
		}

	}
	begin := left + right
	part1 = begin[0:8]
	part2 = begin[8:16]
	part3 = begin[16:24]
	part4 = begin[24:32]
	part1Int, _ = strconv.ParseInt(part1, 2, 64)
	part2Int, _ = strconv.ParseInt(part2, 2, 64)
	part3Int, _ = strconv.ParseInt(part3, 2, 64)
	part4Int, _ = strconv.ParseInt(part4, 2, 64)
	cidrPtr.Begin = strconv.FormatInt(part1Int, 10) + "." +
		strconv.FormatInt(part2Int, 10) + "." +
		strconv.FormatInt(part3Int, 10) + "." +
		strconv.FormatInt(part4Int, 10)
	cidrPtr.BeginNo, _ = strconv.ParseInt(begin, 2, 64)
	cidrPtr.IpCount = cidrPtr.EndNo - cidrPtr.BeginNo + 1
	return cidrPtr
}

func (cidrPtr *Cidr) Translate() *Cidr {
	cidrPtr.Mask = cidrPtr.GetMask()
	cidrPtr.GetBeginEndIp()
	return cidrPtr
}

func (cidrPtr *Cidr) IsInclude(cidr string) bool {
	ipNo := GetIpNo(cidr)
	if ipNo >= cidrPtr.BeginNo && ipNo <= cidrPtr.EndNo {
		return true
	} else {
		return false
	}
}

func GetIpNo(cidr string) int64 {
	partList := strings.Split(cidr, ".")
	ipBin := ""
	for _, part := range partList {
		ipNo, _ := strconv.Atoi(part)
		bin := strconv.FormatInt(int64(ipNo), 2)
		if len(bin) < 8 {
			rest := 8 - len(bin)
			fillZero := ""
			for i := 0; i < rest; i++ {
				fillZero += "0"
			}
			bin = fillZero + bin
		}
		ipBin += bin
	}
	ipNo, _ := strconv.ParseInt(ipBin, 2, 64)
	return ipNo
}
