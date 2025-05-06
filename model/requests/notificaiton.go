package requests

type Notification struct {
	Title   string `json:"title"`
	Message string `json:"message"`
	UserID  int
}
