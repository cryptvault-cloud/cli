module github.com/cryptvault-cloud/vault-cli

go 1.21

toolchain go1.22.1

require (
	github.com/cryptvault-cloud/api v0.2.0
	github.com/cryptvault-cloud/helper v0.1.2
	github.com/urfave/cli/v2 v2.27.1
	github.com/vektah/gqlparser/v2 v2.5.11
	go.uber.org/zap v1.26.0
)

require (
	github.com/Khan/genqlient v0.6.0 // indirect
	github.com/cpuguy83/go-md2man/v2 v2.0.3 // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/xrash/smetrics v0.0.0-20201216005158-039620a65673 // indirect
	go.uber.org/goleak v1.3.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/crypto v0.21.0 // indirect
	golang.org/x/sys v0.18.0 // indirect
)

// replace github.com/cryptvault-cloud/api v0.0.5 => ../api
