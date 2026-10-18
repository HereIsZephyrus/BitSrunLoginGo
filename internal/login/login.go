package login

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/Mmx233/BackoffCli/backoff"
	"github.com/Mmx233/BitSrunLoginGo/internal/config"
	"github.com/Mmx233/BitSrunLoginGo/internal/config/flags"
	"github.com/Mmx233/BitSrunLoginGo/internal/config/keys"
	"github.com/Mmx233/BitSrunLoginGo/internal/dns"
	"github.com/Mmx233/BitSrunLoginGo/internal/http_client"
	"github.com/Mmx233/BitSrunLoginGo/pkg/srun"
	"github.com/Mmx233/BitSrunLoginGo/tools"
	log "github.com/sirupsen/logrus"
)

var ipLast string
var debugTip sync.Once

// 守护模式继续查询在线状态，但不重复提交已被服务器拒绝的凭据。
var loginBlocks sync.Map

type loginKey struct {
	Form      srun.LoginForm
	Acid      string
	Interface string
}

type Conf struct {
	Logger                      log.FieldLogger
	IsOnlineDetectLogDebugLevel bool
}

// resolveInterface 解析 -i 指定的网卡，失败时返回 nil 以回退到默认网卡。
// 每个登录周期都重新解析，保证网卡 IP 变化后能被感知。
func resolveInterface(logger log.FieldLogger, name string) *tools.Eth {
	netEth, err := net.InterfaceByName(name)
	if err != nil {
		logger.Warnf("获取指定网卡 %s 失败，使用默认网卡: %v", name, err)
		return nil
	}
	eth, err := tools.ConvertInterface(logger, *netEth)
	if err != nil {
		logger.Warnf("获取指定网卡 %s ip 地址失败，使用默认网卡: %v", name, err)
		return nil
	}
	if eth == nil {
		logger.Warnf("指定网卡 %s 无可用 ip 地址，使用默认网卡", name)
		return nil
	}
	logger.Debugf("使用指定网卡 %s ip: %s", eth.Name, eth.Addr.String())
	return eth
}

func formForInterface(logger log.FieldLogger, eth *tools.Eth) *srun.LoginForm {
	form := *config.Form
	if eth == nil {
		return &form
	}
	if override, ok := config.Settings.InterfaceForms[eth.Name]; ok {
		form = override.Apply(form)
		logger.Debugf("网卡 %s 应用登录参数覆盖", eth.Name)
	}
	return &form
}

func Login(conf Conf) error {
	logger := conf.Logger
	if config.Settings.Basic.Interfaces == "" { //单网卡
		var eth *tools.Eth
		if flags.Interface != "" {
			eth = resolveInterface(logger, flags.Interface)
		}
		err := Single(SingleConf{
			Conf: conf,
			Eth:  eth,
			Meta: config.Meta,
			Form: formForInterface(logger, eth),
		})
		if err != nil {
			logger.Errorln("登录出错: ", err)
			debugTip.Do(func() {
				if !config.Settings.Log.DebugLevel {
					logger.Infoln("开启调试日志 (debug_level) 获取详细信息")
				}
			})
		}
		return err
	}
	//多网卡
	return Interfaces(conf)
}

func ddns(logger log.FieldLogger, ip string, httpClient *http.Client) error {
	return dns.Run(&dns.Config{
		Logger:   logger.WithField(keys.LogLoginModule, "ddns"),
		Provider: config.Settings.DDNS.Provider,
		IP:       ip,
		Domain:   config.Settings.DDNS.Domain,
		TTL:      config.Settings.DDNS.TTL,
		Conf:     config.Settings.DDNS.Config,
		Http:     httpClient,
	})
}

func Interfaces(conf Conf) error {
	logger := conf.Logger
	interfaces, err := tools.GetInterfaceAddr(logger, config.Settings.Basic.Interfaces)
	if err != nil {
		return err
	}
	var interval = time.Duration(config.Settings.Basic.InterfacesInterval) * time.Second
	var errCount int
	for i, eth := range interfaces {
		logger.Infoln("使用网卡: ", eth.Name)

		if err := Single(SingleConf{
			Conf: conf,
			Eth:  &eth,
			Meta: config.Meta,
			Form: formForInterface(logger, &eth),
		}); err != nil {
			logger.Errorf("网卡 %s 登录出错: %v", eth.Name, err)
			errCount++
		}
		if i != len(interfaces)-1 {
			time.Sleep(interval)
		}
	}
	if errCount > 0 {
		return errors.New("multi interface login not completely succeed")
	}
	return nil
}

type SingleConf struct {
	Conf
	Eth  *tools.Eth
	Meta *srun.LoginMeta
	Form *srun.LoginForm
}

func Single(conf SingleConf) error {
	if config.Settings.Backoff.Enable {
		var terminalErr error
		err := backoff.NewInstance(func(ctx context.Context) error {
			err := doLogin(conf)
			if srun.IsUserActionRequired(err) {
				terminalErr = err
				return nil // 结束退避后向调用方返回真实的认证错误。
			}
			return err
		}, config.BackoffConfig).Run(context.TODO())
		if terminalErr != nil {
			return terminalErr
		}
		return err
	}
	return doLogin(conf)
}

func doLogin(conf SingleConf) error {
	if conf.Form == nil || conf.Meta == nil {
		panic("login: Form and Meta must not be nil")
	}

	logger := conf.Logger

	// 登录配置初始化
	httpClient := http_client.ClientSelect(conf.Eth)
	srunClient := srun.New(&srun.Conf{
		Logger: logger,
		Https:  config.Settings.Basic.Https,
		LoginInfo: srun.LoginInfo{
			Form: *conf.Form,
			Meta: *conf.Meta,
		},
		Client:       httpClient,
		CustomHeader: config.Settings.CustomHeader,
	})

	srunDetector := srunClient.Api.NewDetector()

	if flags.AutoAcid {
		acid, err := srunDetector.WithLogger(logger.WithField(keys.LogLoginModule, "acid")).DetectAcid()
		if err != nil {
			logger.Warnf("获取 nasId 失败，使用配置 meta.acid: %v", err)
		} else {
			logger.Debugf("使用探测 nasId: %s", acid)
			srunClient.LoginInfo.Meta.Acid = acid
		}
	}

	// 选择输出函数
	var _Println func(args ...interface{})
	if conf.IsOnlineDetectLogDebugLevel {
		_Println = logger.Debugln
	} else {
		_Println = logger.Infoln
	}

	_Println("正在获取登录状态")

	online, ip, err := srunClient.LoginStatus()
	if err != nil {
		return err
	}
	clientIp := *ip
	logger.Debugln("认证客户端 ip: ", clientIp)
	key := loginKey{Form: *conf.Form, Acid: srunClient.LoginInfo.Meta.Acid}
	if conf.Eth != nil {
		key.Interface = conf.Eth.Name
	}

	// 登录执行

	if *online {
		loginBlocks.Delete(key)
		_Println("已登录~")

		if config.Settings.DDNS.Enable && config.Settings.Guardian.Enable && ipLast != clientIp {
			if ddns(logger, clientIp, httpClient) == nil {
				ipLast = clientIp
			}
		}

		return nil
	}

	if blocked, ok := loginBlocks.Load(key); ok {
		return blocked.(error)
	}
	logger.Infoln("检测到用户未登录，开始尝试登录...")

	if err = srunClient.DoLogin(clientIp); err != nil {
		if srun.IsUserActionRequired(err) {
			loginBlocks.Store(key, err)
		}
		return err
	}

	logger.Infoln("登录成功~")

	if config.Settings.DDNS.Enable {
		_ = ddns(logger, clientIp, httpClient)
	}

	return nil
}
