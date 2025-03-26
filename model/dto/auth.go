package dto

import "net"

type Authorization struct {
	AccessToken  string
	RefreshToken string
}

type Login struct {
	Username       string
	Password       string
	DeviceIdentity string
	IPAddress      net.IP
	UserAgent      string
}
