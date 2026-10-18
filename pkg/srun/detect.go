package srun

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"

	log "github.com/sirupsen/logrus"
)

func (a *Api) NewDetector() *Detector {
	return &Detector{Logger: a.Logger, api: a}
}

type Detector struct {
	Logger log.FieldLogger
	api    *Api
}

func (d *Detector) WithLogger(logger log.FieldLogger) *Detector {
	detector := *d
	detector.Logger = logger
	detector.api = d.api.WithLogger(logger)
	return &detector
}

// detect 从入口跳转中获取网络参数，不下载登录模板或执行页面脚本。
func (d *Detector) detect() error {
	if d.api.params != nil {
		return nil
	}
	base, err := url.Parse(d.api.BaseUrl)
	if err != nil {
		return err
	}
	addr := base.ResolveReference(&url.URL{Path: "/api/r/default"})
	params := make(url.Values)
	for redirects := 0; redirects < 10; redirects++ {
		query := addr.Query()
		for _, key := range []string{"nasId", "switchip", "mac"} {
			if value := query.Get(key); value != "" {
				params.Set(key, value)
			}
		}
		ip := query.Get("wlanuserip")
		if ip == "" {
			ip = query.Get("ip")
		}
		if ip != "" {
			parsed := net.ParseIP(ip)
			if parsed == nil || parsed.To4() == nil {
				return errors.New("认证入口未返回有效的客户端 IPv4")
			}
			params.Set("userIpv4", parsed.String())
			d.api.params = params
			return nil
		}

		d.Logger.Debugln("HTTP GET", addr.Scheme+"://"+addr.Host+addr.Path)
		req, err := http.NewRequest(http.MethodGet, addr.String(), nil)
		if err != nil {
			return err
		}
		for k, v := range d.api.CustomHeader {
			req.Header.Set(k, fmt.Sprint(v))
		}
		resp, err := d.api.NoDirect.Do(req)
		if err != nil {
			return err
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther,
			http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		default:
			return fmt.Errorf("认证入口未返回网络参数: HTTP %d", resp.StatusCode)
		}
		location := resp.Header.Get("Location")
		if location == "" {
			return errors.New("认证入口缺少 Location")
		}
		next, err := url.Parse(location)
		if err != nil {
			return err
		}
		addr = addr.ResolveReference(next)
		if addr.Host != base.Host || addr.User != nil || (addr.Scheme != "http" && addr.Scheme != "https") {
			return errors.New("认证入口跳转到了其他服务器或不支持的协议")
		}
		// CUG 的 Location 可能使用 HTTP；后续请求继续使用配置的协议。
		addr.Scheme = base.Scheme
	}
	return errors.New("认证入口跳转次数超过限制")
}

// DetectAcid 返回 CUG 的 nasId，沿用现有 acid 配置及命令行参数。
func (d *Detector) DetectAcid() (string, error) {
	if err := d.detect(); err != nil {
		return "", err
	}
	if acid := d.api.params.Get("nasId"); acid != "" {
		return acid, nil
	}
	return "", ErrAcidCannotFound
}

func (d *Detector) DetectIp() (string, error) {
	if err := d.detect(); err != nil {
		return "", err
	}
	return d.api.params.Get("userIpv4"), nil
}

func (d *Detector) Reset() {
	d.api.params = nil
	d.api.csrfToken = ""
}
