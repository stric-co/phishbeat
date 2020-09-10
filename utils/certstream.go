package certstream

import (
	"encoding/json"
	"github.com/gorilla/websocket"
	"github.com/pkg/errors"
	"time"
)

const (
	pingPeriod = 15 * time.Second
)
type CTLogItem struct {
	MessageType string `json:"message_type"`
	Data        struct {
		UpdateType string `json:"update_type"`
		LeafCert   struct {
			Subject struct {
				Aggregated string      `json:"aggregated"`
				C          interface{} `json:"C"`
				ST         interface{} `json:"ST"`
				L          interface{} `json:"L"`
				O          interface{} `json:"O"`
				OU         interface{} `json:"OU"`
				CN         string      `json:"CN"`
			} `json:"subject"`
			Extensions struct {
				KeyUsage               string `json:"keyUsage"`
				ExtendedKeyUsage       string `json:"extendedKeyUsage"`
				BasicConstraints       string `json:"basicConstraints"`
				SubjectKeyIdentifier   string `json:"subjectKeyIdentifier"`
				AuthorityKeyIdentifier string `json:"authorityKeyIdentifier"`
				AuthorityInfoAccess    string `json:"authorityInfoAccess"`
				SubjectAltName         string `json:"subjectAltName"`
				CertificatePolicies    string `json:"certificatePolicies"`
			} `json:"extensions"`
			NotBefore    float64  `json:"not_before"`
			NotAfter     float64  `json:"not_after"`
			SerialNumber string   `json:"serial_number"`
			Fingerprint  string   `json:"fingerprint"`
			AsDer        string   `json:"as_der"`
			AllDomains   []string `json:"all_domains"`
		} `json:"leaf_cert"`
		Chain []struct {
			Subject struct {
				Aggregated string      `json:"aggregated"`
				C          string      `json:"C"`
				ST         interface{} `json:"ST"`
				L          interface{} `json:"L"`
				O          string      `json:"O"`
				OU         interface{} `json:"OU"`
				CN         string      `json:"CN"`
			} `json:"subject"`
			Extensions struct {
				BasicConstraints       string `json:"basicConstraints"`
				KeyUsage               string `json:"keyUsage"`
				AuthorityInfoAccess    string `json:"authorityInfoAccess"`
				AuthorityKeyIdentifier string `json:"authorityKeyIdentifier"`
				CertificatePolicies    string `json:"certificatePolicies"`
				CrlDistributionPoints  string `json:"crlDistributionPoints"`
				SubjectKeyIdentifier   string `json:"subjectKeyIdentifier"`
			} `json:"extensions,omitempty"`
			NotBefore    float64 `json:"not_before"`
			NotAfter     float64 `json:"not_after"`
			SerialNumber string  `json:"serial_number"`
			Fingerprint  string  `json:"fingerprint"`
			AsDer        string  `json:"as_der"`
		} `json:"chain"`
		CertIndex int     `json:"cert_index"`
		Seen      float64 `json:"seen"`
		Source    struct {
			URL  string `json:"url"`
			Name string `json:"name"`
		} `json:"source"`
	} `json:"data"`
}

func CertStreamEventStream(skipHeartbeats bool, certstreamEndpoint string) (chan CTLogItem, chan error) {
	outputStream := make(chan CTLogItem)
	errStream := make(chan error)

	go func() {
		for {
			c, _, err := websocket.DefaultDialer.Dial(certstreamEndpoint, nil)
			if err != nil {
				errStream <- errors.Wrap(err, "Error connecting to certstream! Sleeping a few seconds and reconnecting... ")
				time.Sleep(5 * time.Second)
				continue
			}
			defer c.Close()
			defer close(outputStream)
			done := make(chan struct{})
			go func() {
				ticker := time.NewTicker(pingPeriod)
				defer ticker.Stop()

				for {
					select {
					case <-ticker.C:
						err := c.WriteMessage(websocket.PingMessage, nil)
						if err != nil{
							errStream <- errors.Wrap(err, "Failed to write websocket ping.")
						}
					case <-done:
						return
					}
				}
			}()
			for {
				err := c.SetReadDeadline(time.Now().Add(15 * time.Second))
				if err != nil{
					errStream <- errors.Wrap(err, "Error Setting Read Deadline!")
					err := c.Close()
					if err != nil{
						errStream <- errors.Wrap(err, "Error stopping stream after read deadline failure!")
						break
					}
					break
				}
				_, byteArray, err := c.ReadMessage()
				if err != nil {
					errStream <- errors.Wrap(err, "Error decoding json frame!")
					err := c.Close()
					if err != nil{
						errStream <- errors.Wrap(err, "Error stopping stream after failing to read json frame!")
						break
					}
					break
				}
				var ctItem CTLogItem
				err = json.Unmarshal(byteArray, &ctItem)
				if err != nil {
					errStream <- errors.Wrap(err, "Error unmarshalling json CT object!")
					err := c.Close()
					if err != nil{
						errStream <- errors.Wrap(err, "Error stopping stream after failing to unmarshal json CT object!")
						break
					}
					break
				}
				if skipHeartbeats && ctItem.MessageType == "heartbeat" {
					continue
				}
				outputStream <- ctItem
			}
			close(done)
		}
	}()
	return outputStream, errStream
}
