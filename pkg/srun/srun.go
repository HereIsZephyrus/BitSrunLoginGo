package srun

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
)

type Conf struct {
	Https        bool
	LoginInfo    LoginInfo
	Client       *http.Client
	CustomHeader map[string]interface{}
	Logger       log.FieldLogger
}

func New(conf *Conf) *Srun {
	logger := conf.Logger
	if logger == nil {
		logger = log.New()
	}
	client := &Srun{LoginInfo: conf.LoginInfo, Logger: logger}
	client.Api.Init(&ApiConfig{
		Https: conf.Https, Domain: conf.LoginInfo.Form.Domain,
		Client: conf.Client, CustomHeader: conf.CustomHeader, Logger: logger,
	})
	return client
}

type Srun struct {
	LoginInfo LoginInfo
	Api       Api
	Logger    log.FieldLogger
}

func (c *Srun) networkParams() (url.Values, error) {
	if _, err := c.Api.NewDetector().DetectIp(); err != nil {
		return nil, err
	}
	params := make(url.Values)
	for key, values := range c.Api.params {
		params[key] = append([]string(nil), values...)
	}
	if c.LoginInfo.Meta.Acid != "" {
		params.Set("nasId", c.LoginInfo.Meta.Acid)
	}
	if nasID, err := strconv.Atoi(params.Get("nasId")); err != nil || nasID <= 0 {
		return nil, errors.New("缺少有效的 nasId，请配置 meta.acid 或使用 --auto-acid")
	}
	if mac := params.Get("mac"); mac != "" {
		params.Set("userMac", mac)
		params.Del("mac")
	}
	return params, nil
}

// LoginStatus 返回认证状态和客户端 IPv4；无法确认状态时返回错误。
func (c *Srun) LoginStatus() (online *bool, ip *string, err error) {
	params, err := c.networkParams()
	if err != nil {
		return nil, nil, err
	}
	res, err := c.Api.GetUserInfo(params)
	if err != nil {
		return nil, nil, err
	}
	clientIP := params.Get("userIpv4")
	var isOnline bool
	switch *res.Code {
	case 0:
		if res.Online == nil {
			return nil, nil, ErrResultCannotFound
		}
		isOnline = true
		if res.Online.UserIpv4 != "" {
			parsed := net.ParseIP(res.Online.UserIpv4)
			if parsed == nil || parsed.To4() == nil {
				return nil, nil, errors.New("在线状态返回了无效的客户端 IPv4")
			}
			clientIP = parsed.String()
		}
	case 1:
		isOnline = false
	default:
		return nil, nil, fmt.Errorf("查询登录状态失败: code=%d", *res.Code)
	}
	return &isOnline, &clientIP, nil
}

func (c *Srun) responseError(res *accountResponse) error {
	kind := ErrAuthentication
	if *res.Code == 2 {
		kind = ErrCaptchaRequired
	} else if *res.Code == 0 && res.IsChangePwd == 1 {
		kind = ErrPasswordChange
	}
	message := res.Msg
	for _, secret := range []string{c.LoginInfo.Form.Password, c.Api.csrfToken} {
		if secret != "" {
			message = strings.ReplaceAll(message, secret, "[redacted]")
		}
	}
	return fmt.Errorf("%w: code=%d %s", kind, *res.Code, message)
}

func (c *Srun) DoLogin(clientIP string) error {
	if c.LoginInfo.Form.Username == "" || c.LoginInfo.Form.Password == "" {
		return fmt.Errorf("%w: 账号或密码为空", ErrAuthentication)
	}
	form, err := c.networkParams()
	if err != nil {
		return err
	}
	if clientIP != "" && clientIP != form.Get("userIpv4") {
		return errors.New("客户端 IP 与认证入口不一致，请重新检测")
	}
	form.Set("username", c.LoginInfo.Form.Username)
	form.Set("password", c.LoginInfo.Form.Password)
	form.Set("isp", c.LoginInfo.Form.UserType)

	c.Logger.Debugln("检查账号")
	res, err := c.Api.Check(form)
	if err != nil {
		return err
	}
	if *res.Code != 0 || res.IsChangePwd == 1 {
		return c.responseError(res)
	}

	c.Logger.Debugln("发送登录请求")
	res, err = c.Api.Login(form)
	if err != nil {
		return err
	}
	if *res.Code != 0 {
		return c.responseError(res)
	}
	online, _, err := c.LoginStatus()
	if err != nil {
		return err
	}
	if !*online {
		return errors.New("登录请求已返回，但服务器尚未确认在线")
	}
	return nil
}
