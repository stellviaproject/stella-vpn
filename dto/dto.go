package dto

type LoginForm struct {
	Username string `json:"username"`
	Password string `json:"password"`
	OTP      string `json:"otp"`
}

type LoginResponse struct {
	Token string `json:"token"`
	OTP   bool   `json:"otp"`
	Key   string `json:"key"`
	Err   string `json:"err"`
}
