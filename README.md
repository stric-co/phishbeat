# Phishbeat

Welcome to Phishbeat, a lightweight shipper, designed to monitor Certificate Transparency logs for Phishing domains.

## Architecture
Phishbeat hooks into [Certificate Transparency (CT) logs](https://www.certificate-transparency.org/) to get a realtime feed of certificate generation. This allows Phishbeat to detect the realtime usage of domains. Generally, when a domain is registered with one of the larger domain registrars, a dummy "this domain has been bought" site is created, usually with a SSL certificate.
![alt text](https://github.com/stric-co/phishbeat/raw/master/images/architecture.png "Architecture")

You can use the [CaliDog certstream server](https://certstream.calidog.io/) or [run your own](https://github.com/CaliDog/certstream-server).

## Getting Started with Phishbeat

### Configuration
All configuration is done in the `phishbeat.yml` file. This file follows the common [Elastic configuration](https://www.elastic.co/guide/en/beats/libbeat/current/config-file-format.html). Phishbeat works on both [Elastic Cloud](https://cloud.elastic.co) and On Prem.

Certonly mode:
```yaml
phishbeat:
  domain: "stric.co"
  certstream:
    endpoint: "wss://certstream.calidog.io"
    skipheartbeats: false
    certonly: true
output.elasticsearch:
  hosts: ["localhost:9200"]
cloud.id: '${CLOUD_ID}'
cloud.auth: 'elastic:${CLOUD_PASS}'
```

Regular mode:
```yaml
phishbeat:
  domain: "stric.co"
  certstream:
    endpoint: "wss://certstream.calidog.io"
    skipheartbeats: false
    certonly: false
output.elasticsearch:
  hosts: ["localhost:9200"]
cloud.id: '${CLOUD_ID}'
cloud.auth: 'elastic:${CLOUD_PASS}'
```

### Indexed Data
Phishbeat has two operating modes:
- Certonly: All CT events are saved to Elasticsearch
- Regular: Phishing domains are generated and monitored, based off the legitimate domain provided

Certonly data output:
```json
{
  "message_type": "certificate_update",
  "data": {
    "source": {
      "url": "ct.googleapis.com/logs/argon2021/",
      "name": "Google 'Argon2021' log"
    },
    "update_type": "PrecertLogEntry",
    "leaf_cert": {
      "not_before": 1.5973632E+9,
      "not_after": 1.6289424E+9,
      "serial_number": "9285A2EA75EA6293E99E2FBAF57F18B",
      "fingerprint": "62:99:35:5E:DF:56:C3:43:A8:0C:F1:17:72:29:61:F5:4D:52:93:BE",
      "as_der": "",
      "all_domains": [
        "*.ccproven.com",
        "ccproven.com",
        "sni.cloudflaressl.com"
      ],
      "subject": {
        "O": "Cloudflare, Inc.",
        "CN": "sni.cloudflaressl.com",
        "aggregated": "/C=US/CN=sni.cloudflaressl.com/L=San Francisco/O=Cloudflare, Inc./ST=CA",
        "C": "US",
        "ST": "CA",
        "L": "San Francisco"
      },
      "extensions": {
        "authorityInfoAccess": "<redacted>",
        "subjectAltName": "DNS:sni.cloudflaressl.com, DNS:ccproven.com, DNS:*.ccproven.com",
        "certificatePolicies": "<redacted>",
        "keyUsage": "Digital Signature",
        "extendedKeyUsage": "TLS Web server authentication, TLS Web client authentication",
        "basicConstraints": "CA:FALSE",
        "subjectKeyIdentifier": "43:87:80:BD:BC:DE:DF:33:FB:24:EF:ED:CC:46:CB:AC:7F:93:E3:7A",
        "authorityKeyIdentifier": "<redacted>"
      }
    },
    "chain": [
      {
        "extensions": {
          "basicConstraints": "CA:TRUE",
          "keyUsage": "Digital Signature, Key Cert Sign, C R L Sign",
          "authorityInfoAccess": "<redacted>",
          "authorityKeyIdentifier": "<redacted>",
          "certificatePolicies": "<redacted>",
          "crlDistributionPoints": "<redacted>",
          "subjectKeyIdentifier": "A5:CE:37:EA:EB:B0:75:0E:94:67:88:B4:45:FA:D9:24:10:87:96:1F"
        },
        "not_before": 1580129288,
        "not_after": 1735689599,
        "serial_number": "A3787645E5FB48C224EFD1BED140C3C",
        "fingerprint": "B3:DD:76:06:D2:B5:A8:B4:A1:37:71:DB:EC:C9:EE:1C:EC:AF:A3:8A",
        "as_der": "",
        "subject": {
          "aggregated": "/C=US/CN=Cloudflare Inc ECC CA-3/O=Cloudflare, Inc.",
          "C": "US",
          "O": "Cloudflare, Inc.",
          "CN": "Cloudflare Inc ECC CA-3"
        }
      },
      {
        "as_der": "",
        "subject": {
          "C": "IE",
          "O": "Baltimore",
          "OU": "CyberTrust",
          "CN": "Baltimore CyberTrust Root",
          "aggregated": "/C=IE/CN=Baltimore CyberTrust Root/O=Baltimore/OU=CyberTrust"
        },
        "extensions": {
          "subjectKeyIdentifier": "E5:9D:59:30:82:47:58:CC:AC:FA:08:54:36:86:7B:3A:B5:04:4D:F0",
          "basicConstraints": "CA:TRUE",
          "keyUsage": "Key Cert Sign, C R L Sign",
          "authorityInfoAccess": "",
          "authorityKeyIdentifier": "",
          "certificatePolicies": "",
          "crlDistributionPoints": ""
        },
        "not_before": 9.5815716E+8,
        "not_after": 1.74709434E+9,
        "serial_number": "20000B9",
        "fingerprint": "D4:DE:20:D0:5E:66:FC:53:FE:1A:50:88:2C:78:DB:28:52:CA:E4:74"
      }
    ],
    "cert_index": 76778233,
    "seen": 1597386909.623113
  }
}
```
Regular data output:
```json
{
  "@timestamp" : "2020-09-10T11:31:03.878Z",
  "domain" : "stri.co",
  "original_domain" : "stric.co",
  "type": "omission"
}
```


### Elastic SIEM Detections
In the `_detections` folder, you will find two detection rules for the Elastic SIEM.

### Machine Learning
In the `_ml` folder, you'll find some Elastic Machine Learning jobs to compliment Phishbeat.

### Credit
Credit goes to:
- [DNSMorph](https://github.com/netevert/dnsmorph) for the logic around the generation of squatted domains.
- [Calidog](https://github.com/CaliDog/certstream-go) for the base of the Certstream Go client, and the Certstream server.
