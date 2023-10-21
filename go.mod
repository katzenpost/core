// Deprecated: use github.com/katzenpost/katzenpost instead.
module github.com/katzenpost/core

go 1.12

require (
	git.schwanenlied.me/yawning/aez.git v0.0.0-20180408160647-ec7426b44926
	git.schwanenlied.me/yawning/bsaes.git v0.0.0-20190320102049-26d1add596b6
	github.com/fxamacker/cbor/v2 v2.3.0
	github.com/katzenpost/chacha20 v0.0.0-20190910113340-7ce890d6a556
	github.com/katzenpost/noise v0.0.2
	github.com/stretchr/testify v1.4.0
	github.com/ugorji/go/codec v1.1.7
	golang.org/x/crypto v0.0.0-20201221181555-eec23a3978ad
	gopkg.in/op/go-logging.v1 v1.0.0-20160211212156-b2cb9fa56473
)

retract (
	v0.0.15
	v0.0.14
	v0.0.13
	v0.0.12
	v0.0.11
	v0.0.10
	v0.0.9
	v0.0.8
	v0.0.7
	v0.0.6
	v0.0.5
	v0.0.4
	v0.0.3
	v0.0.2
	v0.0.1
)
