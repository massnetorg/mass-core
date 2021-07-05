module github.com/massnetorg/mass-core

go 1.13

require (
	github.com/btcsuite/btcd v0.20.1-beta
	github.com/davecgh/go-spew v1.1.1
	github.com/facebookgo/ensure v0.0.0-20160127193407-b4ab57deab51 // indirect
	github.com/facebookgo/stack v0.0.0-20160209184415-751773369052 // indirect
	github.com/facebookgo/subset v0.0.0-20150612182917-8dac2c3c4870 // indirect
	github.com/fastly/go-utils v0.0.0-20180712184237-d95a45783239 // indirect
	github.com/gogo/protobuf v1.2.1
	github.com/golang/groupcache v0.0.0-20191227052852-215e87163ea7
	github.com/golang/protobuf v1.4.2
	github.com/jehiah/go-strftime v0.0.0-20171201141054-1d33003b3869 // indirect
	github.com/lestrrat/go-envload v0.0.0-20180220120943-6ed08b54a570 // indirect
	github.com/lestrrat/go-file-rotatelogs v0.0.0-20180223000712-d3151e2a480f
	github.com/lestrrat/go-strftime v0.0.0-20180220042222-ba3bf9c1d042 // indirect
	github.com/massnetorg/tendermint v1.0.0
	github.com/pkg/errors v0.8.1
	github.com/rifflock/lfshook v0.0.0-20180920164130-b9218ef580f5
	github.com/shopspring/decimal v1.2.0
	github.com/sirupsen/logrus v1.2.0
	github.com/stretchr/testify v1.7.0
	github.com/syndtr/goleveldb v1.0.1-0.20210305035536-64b5b1c73954
	github.com/tebeka/strftime v0.1.3 // indirect
	github.com/tecbot/gorocksdb v0.0.0-20190705090504-162552197222
	golang.org/x/crypto v0.0.0-20210322153248-0c34fe9e7dc2
	golang.org/x/sys v0.0.0-20210420205809-ac73e9fd8988
	gopkg.in/fatih/set.v0 v0.2.1
	gopkg.in/karalabe/cookiejar.v2 v2.0.0-20150724131613-8dcd6a7f4951
)

replace github.com/massnetorg/mass-core => ./
