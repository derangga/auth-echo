package queue

type LogDeviceLogin struct {
	UserID         int    `json:"user_id"`
	DeviceIdentity string `json:"device_identity"`
	SessionId      string `json:"session_id"`
	IPAddress      string `json:"ip_address"`
	UserAgent      string `db:"user_agent"`
}
