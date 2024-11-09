// spanner provides our data storage API backed by Google Cloud Spanner
package spanner

import (
	"cloud.google.com/go/spanner"
)

const name = "github.com/AscendiumApps/ga-lite-app/spanner"

type StorageDriver struct {
	spanner *spanner.Client
}

func NewStorageDriver(client *spanner.Client) *StorageDriver {
	return &StorageDriver{
		spanner: client,
	}
}

func (d *StorageDriver) Close() {
	d.spanner.Close()
}
