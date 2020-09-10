module github.com/stric-co/phishbeat

go 1.14

replace (
	github.com/Azure/go-autorest => github.com/Azure/go-autorest v12.2.0+incompatible
	github.com/Shopify/sarama => github.com/elastic/sarama v1.19.1-0.20200629123429-0e7b69039eec
	github.com/cucumber/godog => github.com/cucumber/godog v0.8.1
	github.com/docker/docker => github.com/docker/engine v0.0.0-20191113042239-ea84732a7725
	github.com/docker/go-plugins-helpers => github.com/elastic/go-plugins-helpers v0.0.0-20200207104224-bdf17607b79f
	github.com/dop251/goja => github.com/andrewkroh/goja v0.0.0-20190128172624-dd2ac4456e20
	github.com/fsnotify/fsevents => github.com/elastic/fsevents v0.0.0-20181029231046-e1d381a4d270
	github.com/fsnotify/fsnotify => github.com/adriansr/fsnotify v0.0.0-20180417234312-c9bbe1f46f1d
	github.com/google/gopacket => github.com/adriansr/gopacket v1.1.18-0.20200327165309-dd62abfa8a41
	github.com/insomniacslk/dhcp => github.com/elastic/dhcp v0.0.0-20200227161230-57ec251c7eb3 // indirect
	github.com/tonistiigi/fifo => github.com/containerd/fifo v0.0.0-20190816180239-bda0ff6ed73c
	golang.org/x/tools => golang.org/x/tools v0.0.0-20200602230032-c00d67ef29d0 // release 1.14
)

require (
	github.com/CaliDog/certstream-go v0.0.0-20200713031452-eca7997412f1 // indirect
	github.com/akavel/rsrc v0.9.0 // indirect
	github.com/dlclark/regexp2 v1.2.0 // indirect
	github.com/dop251/goja v0.0.0-20200721192441-a695b0cdd498 // indirect
	github.com/dop251/goja_nodejs v0.0.0-20200706082813-b2775b86b9e0 // indirect
	github.com/elastic/beats/v7 v7.0.0-alpha2.0.20200731151131-43bbf51c432d
	github.com/elastic/go-sysinfo v1.4.0 // indirect
	github.com/fatih/color v1.9.0 // indirect
	github.com/go-sourcemap/sourcemap v2.1.3+incompatible // indirect
	github.com/gorilla/websocket v1.4.1
	github.com/imroc/req v0.3.0
	github.com/jmoiron/jsonq v0.0.0-20150511023944-e874b168d07e
	github.com/josephspurrier/goversioninfo v1.2.0 // indirect
	github.com/magefile/mage v1.10.0
	github.com/mattn/go-colorable v0.1.7 // indirect
	github.com/mitchellh/gox v1.0.1
	github.com/mitchellh/hashstructure v1.0.0 // indirect
	github.com/pierrre/gotestcover v0.0.0-20160517101806-924dca7d15f0
	github.com/pkg/errors v0.9.1
	github.com/prometheus/procfs v0.1.3 // indirect
	github.com/rcrowley/go-metrics v0.0.0-20200313005456-10cdbea86bc0 // indirect
	github.com/reviewdog/reviewdog v0.10.1
	github.com/tsg/go-daemon v0.0.0-20200207173439-e704b93fd89b
	github.com/urso/magetools v0.0.0-20200125210132-c2e338f92f3a // indirect
	go.elastic.co/apm v1.8.0 // indirect
	go.elastic.co/ecszap v0.2.0 // indirect
	go.elastic.co/fastjson v1.1.0 // indirect
	go.uber.org/zap v1.15.0 // indirect
	golang.org/x/crypto v0.0.0-20200728195943-123391ffb6de // indirect
	golang.org/x/lint v0.0.0-20200302205851-738671d3881b
	golang.org/x/net v0.0.0-20200707034311-ab3426394381 // indirect
	golang.org/x/sys v0.0.0-20200802091954-4b90ce9b60b3 // indirect
	golang.org/x/text v0.3.3 // indirect
	golang.org/x/tools v0.0.0-20200731060945-b5fad4ed8dd6
	honnef.co/go/tools v0.0.1-2020.1.5 // indirect
	howett.net/plist v0.0.0-20200419221736-3b63eb3a43b5 // indirect
)
