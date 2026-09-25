module github.com/garm-ai/garmd

go 1.26.0

require (
	buf.build/go/protovalidate v1.4.0
	connectrpc.com/connect v1.21.0
	github.com/bufbuild/protocompile v0.14.1
	github.com/garm-ai/garm v0.6.0
	github.com/nats-io/nats-server/v2 v2.15.0 // test only: an embedded server for the transport tests. Not in `go list -deps`, so the CI boundary checks are unaffected.
	github.com/nats-io/nats.go v1.54.0
	github.com/spf13/cobra v1.10.2
	google.golang.org/protobuf v1.36.12
)

require (
	buf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go v1.36.12-20260825204119-511051f7f437.1 // indirect
	cel.dev/cel-go v0.32.0 // indirect
	cel.dev/expr v0.25.3 // indirect
	github.com/antithesishq/antithesis-sdk-go v0.8.0-default-no-op // indirect
	github.com/antlr4-go/antlr/v4 v4.13.1 // indirect
	github.com/google/go-tpm v0.9.8 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/klauspost/compress v1.20.0 // indirect
	github.com/minio/highwayhash v1.0.4 // indirect
	github.com/nats-io/jwt/v2 v2.8.2 // indirect
	github.com/nats-io/nkeys v0.4.16 // indirect
	github.com/nats-io/nuid v1.0.1 // indirect
	github.com/spf13/pflag v1.0.10 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/crypto v0.57.0 // indirect
	golang.org/x/exp v0.0.0-20260820142414-ca536658362e // indirect
	golang.org/x/sync v0.23.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
	golang.org/x/text v0.42.0 // indirect
	golang.org/x/time v0.16.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20260819154853-08b0e4226688 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260819154853-08b0e4226688 // indirect
)
