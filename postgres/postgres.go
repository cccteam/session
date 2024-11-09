package postgres

const name = "github.com/cccteam/session/postgres"

type StorageDriver struct {
	conn Queryer
}

func NewStorageDriver(conn Queryer) *StorageDriver {
	return &StorageDriver{
		conn: conn,
	}
}
