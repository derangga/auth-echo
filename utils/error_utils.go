package utils

func IsNoRowError(err error) bool {
	return err.Error() == "sql: no rows in result set"
}
