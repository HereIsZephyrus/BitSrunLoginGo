package srun

import "errors"

var (
	ErrResultCannotFound = errors.New("result cannot found from response")
	ErrAcidCannotFound   = errors.New("acid not found")
	ErrEnvCannotFound    = errors.New("enc not found")
	ErrAuthentication    = errors.New("认证失败，请检查账号及网络参数后重启")
	ErrCaptchaRequired   = errors.New("需要验证码，请先在浏览器完成认证后重启")
	ErrPasswordChange    = errors.New("需要修改密码，请先在浏览器完成修改后重启")
)

func IsUserActionRequired(err error) bool {
	return errors.Is(err, ErrAuthentication) || errors.Is(err, ErrCaptchaRequired) || errors.Is(err, ErrPasswordChange)
}
