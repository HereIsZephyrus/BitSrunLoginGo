package srun

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

type apiSession struct {
	params    url.Values
	csrfToken string
}

type Api struct {
	BaseUrl      string
	Client       *http.Client
	NoDirect     *http.Client
	CustomHeader map[string]interface{}
	Logger       log.FieldLogger
	*apiSession
}

type ApiConfig struct {
	Https        bool
	Domain       string
	Client       *http.Client
	CustomHeader map[string]interface{}
	Logger       log.FieldLogger
}

func (a *Api) Init(conf *ApiConfig) {
	scheme := "http"
	if conf.Https {
		scheme = "https"
	}
	a.BaseUrl = scheme + "://" + conf.Domain + "/"
	a.CustomHeader = conf.CustomHeader
	a.apiSession = &apiSession{}

	client := http.Client{Timeout: 10 * time.Second}
	if conf.Client != nil {
		client = *conf.Client
	}
	// 每个认证会话独立保存 Cookie，继续使用调用方绑定网卡的 Transport。
	client.Jar, _ = cookiejar.New(nil)
	// API 请求不跟随跳转，防止携带凭据的 POST 被转发到其他地址。
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	a.Client = &client
	a.NoDirect = &client
	a.Logger = conf.Logger
	if a.Logger == nil {
		a.Logger = log.New()
	}
}

func (a *Api) WithLogger(logger log.FieldLogger) *Api {
	api := *a
	api.Logger = logger
	return &api
}

// request 不记录表单、响应正文或会话令牌。
func (a *Api) request(method, path string, values url.Values, result any) error {
	addr := a.BaseUrl + path
	var body io.Reader
	if method == http.MethodGet {
		if len(values) > 0 {
			addr += "?" + values.Encode()
		}
	} else {
		body = strings.NewReader(values.Encode())
	}
	req, err := http.NewRequest(method, addr, body)
	if err != nil {
		return err
	}
	for k, v := range a.CustomHeader {
		req.Header.Set(k, fmt.Sprint(v))
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if a.csrfToken != "" {
		req.Header.Set("X-CSRF-Token", a.csrfToken)
	}
	a.Logger.Debugln("HTTP", method, a.BaseUrl+path)
	resp, err := a.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusForbidden {
			a.csrfToken = ""
		}
		return fmt.Errorf("%s: HTTP %d", path, resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if err = json.Unmarshal(data, result); err != nil {
		return fmt.Errorf(
			"%s: JSON decode failed (HTTP %d, Content-Type=%q, bytes=%d): %w",
			path, resp.StatusCode, resp.Header.Get("Content-Type"), len(data), err,
		)
	}
	return nil
}

func (a *Api) ensureCSRF() error {
	if a.csrfToken != "" {
		return nil
	}
	var result struct {
		Token string `json:"csrf_token"`
	}
	if err := a.request(http.MethodGet, "api/csrf-token", nil, &result); err != nil {
		return err
	}
	if result.Token == "" {
		return fmt.Errorf("csrf-token: %w", ErrResultCannotFound)
	}
	a.csrfToken = result.Token
	return nil
}

func (a *Api) accountRequest(method, action string, values url.Values) (*accountResponse, error) {
	if err := a.ensureCSRF(); err != nil {
		return nil, err
	}
	var result accountResponse
	if err := a.request(method, "api/account/"+action, values, &result); err != nil {
		return nil, err
	}
	if result.Code == nil {
		return nil, fmt.Errorf("account/%s: %w", action, ErrResultCannotFound)
	}
	return &result, nil
}

func (a *Api) GetUserInfo(params url.Values) (*accountResponse, error) {
	return a.accountRequest(http.MethodGet, "status", params)
}

func (a *Api) Check(form url.Values) (*accountResponse, error) {
	return a.accountRequest(http.MethodPost, "check", form)
}

func (a *Api) Login(form url.Values) (*accountResponse, error) {
	return a.accountRequest(http.MethodPost, "login", form)
}
