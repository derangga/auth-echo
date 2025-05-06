package queue

type NotifyUserOtherDevice struct {
	UserID                int    `json:"user_id"`
	CurrentDeviceIdentity string `json:"current_device_identity"`
	IPAddress             string `json:"ip_address"`
}
