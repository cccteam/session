// spanner provides our data storage API backed by Google Cloud Spanner
package spanner

import (
	"cloud.google.com/go/spanner"
)

const name = "github.com/AscendiumApps/ga-lite-app/spanner"

type Client struct {
	spanner *spanner.Client
}

func New(client *spanner.Client) *Client {
	return &Client{
		spanner: client,
	}
}

func (c *Client) Close() {
	c.spanner.Close()
}
