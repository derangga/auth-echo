package requests

type FcmDevice struct {
	UserID         int
	DeviceIdentity string
	Token          string `json:"token" validate:"required"`
}
