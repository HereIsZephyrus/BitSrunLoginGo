package srun

import (
	"encoding/json"
	"errors"
)

type LoginForm struct {
	Domain   string `json:"domain" yaml:"domain"`
	Username string `json:"username" yaml:"username"`
	// CUG 的 isp 参数；当前账号登录页留空，不追加到用户名。
	UserType string `json:"user_type" yaml:"user_type"`
	Password string `json:"password" yaml:"password"`
}

type LoginFormOverride struct {
	Domain   *string `json:"domain,omitempty" yaml:"domain,omitempty"`
	Username *string `json:"username,omitempty" yaml:"username,omitempty"`
	UserType *string `json:"user_type,omitempty" yaml:"user_type,omitempty"`
	Password *string `json:"password,omitempty" yaml:"password,omitempty"`
}

func (o LoginFormOverride) Apply(form LoginForm) LoginForm {
	if o.Domain != nil {
		form.Domain = *o.Domain
	}
	if o.Username != nil {
		form.Username = *o.Username
	}
	if o.UserType != nil {
		form.UserType = *o.UserType
	}
	if o.Password != nil {
		form.Password = *o.Password
	}
	return form
}

type LoginMeta struct {
	N           string `json:"n" yaml:"n"`
	Type        string `json:"type" yaml:"type"`
	Acid        string `json:"acid" yaml:"acid"` // CUG nasId
	Enc         string `json:"enc" yaml:"enc"`
	OS          string `json:"os" yaml:"os"`
	Name        string `json:"name" yaml:"name"`
	InfoPrefix  string `json:"info_prefix" yaml:"info_prefix"`
	DoubleStack bool   `json:"double_stack" yaml:"double_stack"`
}

type LoginInfo struct {
	Form LoginForm
	Meta LoginMeta
}

// CUG 的 isChangePwd 可能返回 JSON 字符串或数字。
type changePasswordFlag int

func (flag *changePasswordFlag) UnmarshalJSON(data []byte) error {
	var value json.Number
	if err := json.Unmarshal(data, &value); err == nil {
		switch value.String() {
		case "0":
			*flag = 0
			return nil
		case "1":
			*flag = 1
			return nil
		}
	}
	return errors.New("isChangePwd: expected 0 or 1 as a number or string")
}

type accountResponse struct {
	Code        *int               `json:"code"`
	Msg         string             `json:"msg"`
	AuthCode    string             `json:"authCode"`
	IsChangePwd changePasswordFlag `json:"isChangePwd"`
	Online      *struct {
		UserIpv4 string `json:"UserIpv4"`
	} `json:"online"`
}
