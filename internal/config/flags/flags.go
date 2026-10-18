package flags

import (
	"flag"
)

var (
	// Path 配置文件路径
	Path string

	Interface string
	Debug     bool
	AutoAcid  bool
	Acid      string
	AutoEnc   bool
)

func init() {
	flag.StringVar(&Path, "config", "Config.yaml", "config path")

	flag.StringVar(&Interface, "interface", "", "specify the eth name")
	flag.BoolVar(&Debug, "debug", false, "enable debug mode")
	flag.BoolVar(&AutoAcid, "auto-acid", false, "auto detect CUG nasId")
	flag.StringVar(&Acid, "acid", "", "specify CUG nasId")
	flag.BoolVar(&AutoEnc, "auto-enc", false, "accepted for compatibility; unused by CUG")

	flag.Parse()
}
