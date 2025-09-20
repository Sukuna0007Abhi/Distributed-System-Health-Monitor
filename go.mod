module github.com/enterprise/distributed-health-monitor

go 1.21

require (
	github.com/nats-io/nats.go v1.31.0
	github.com/segmentio/kafka-go v0.4.45
	github.com/open-policy-agent/opa v0.58.0
	github.com/prometheus/client_golang v1.17.0
	github.com/go-redis/redis/v8 v8.11.5
	github.com/gorilla/mux v1.8.1
	github.com/sirupsen/logrus v1.9.3
	github.com/spf13/cobra v1.8.0
	github.com/spf13/viper v1.17.0
	github.com/google/uuid v1.4.0
	github.com/hashicorp/raft v1.5.0
	github.com/hashicorp/raft-boltdb v0.0.0-20230125174641-2a8082862702
	github.com/spiffe/go-spiffe/v2 v2.1.6
	github.com/golang-jwt/jwt/v5 v5.2.0
	github.com/containerd/ttrpc v1.2.2
	github.com/opencontainers/runtime-spec v1.1.0
	github.com/tensorflow/tensorflow v2.13.0+incompatible
	go.opentelemetry.io/otel v1.21.0
	go.opentelemetry.io/otel/trace v1.21.0
	go.opentelemetry.io/otel/exporters/jaeger v1.17.0
	go.opentelemetry.io/otel/exporters/prometheus v0.44.0
	go.opentelemetry.io/otel/sdk v1.21.0
	go.opentelemetry.io/otel/sdk/metric v1.21.0
	github.com/aws/aws-sdk-go-v2 v1.24.0
	github.com/Azure/azure-sdk-for-go v68.0.0+incompatible
	cloud.google.com/go/compute v1.23.3
	k8s.io/client-go v0.28.4
	k8s.io/apimachinery v0.28.4
	github.com/operator-framework/operator-sdk v1.33.0
)

require (
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.2.0 // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
	github.com/fsnotify/fsnotify v1.7.0 // indirect
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/hashicorp/hcl v1.0.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/klauspost/compress v1.17.4 // indirect
	github.com/magiconair/properties v1.8.7 // indirect
	github.com/matttproud/golang_protobuf_extensions v1.0.4 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/nats-io/nkeys v0.4.7 // indirect
	github.com/nats-io/nuid v1.0.1 // indirect
	github.com/pelletier/go-toml/v2 v2.1.1 // indirect
	github.com/pierrec/lz4/v4 v4.1.19 // indirect
	github.com/prometheus/client_model v0.5.0 // indirect
	github.com/prometheus/common v0.45.0 // indirect
	github.com/prometheus/procfs v0.12.0 // indirect
	github.com/spf13/afero v1.11.0 // indirect
	github.com/spf13/cast v1.6.0 // indirect
	github.com/spf13/jwalterweatherman v1.1.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/subosito/gotenv v1.6.0 // indirect
	golang.org/x/crypto v0.17.0 // indirect
	golang.org/x/net v0.19.0 // indirect
	golang.org/x/sys v0.15.0 // indirect
	golang.org/x/text v0.14.0 // indirect
	google.golang.org/protobuf v1.31.0 // indirect
	gopkg.in/ini.v1 v1.67.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
