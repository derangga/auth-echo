package dto

type Authorization struct {
	AccessToken  string
	RefreshToken string
}

type Login struct {
	Username       string
	Password       string
	DeviceIdentity string
	IPAddress      string
	UserAgent      string
}
