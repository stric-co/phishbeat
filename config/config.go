// Config is put into a different package to prevent cyclic imports in case
// it is needed in several locations

package config

type Config struct {
	Domain 					string	`config:"domain"`
	CertStreamEndpoint 		string	`config:"certstream.endpoint"`
	CertStreamSkipHeartbeat	bool 	`config:"certstream.skipheartbeat"`
	CertOnly				bool	`config:"certstream.certonly"`
}

var DefaultConfig = Config{
	Domain: "example.com",
	CertStreamEndpoint: "wss://certstream.calidog.io",
	CertStreamSkipHeartbeat: false,
	CertOnly: false,
}
