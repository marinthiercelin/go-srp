module github.com/ProtonMail/go-srp

go 1.12

require (
	github.com/ProtonMail/go-crypto v0.0.0-20210428141323-04723f9f07d7
	github.com/cronokirby/safenum v0.11.0
	github.com/jameskeane/bcrypt v0.0.0-20120420032655-c3cd44c1e20f
	github.com/pkg/errors v0.9.1 // indirect
	github.com/stretchr/testify v1.7.0 // indirect
	golang.org/x/mobile v0.0.0-20190910184405-b558ed863381 // indirect
)

replace golang.org/x/mobile => github.com/ProtonMail/go-mobile v0.0.0-20201014085805-7a2d68bf792f

replace github.com/jameskeane/bcrypt => github.com/ProtonMail/bcrypt v0.0.0-20210511135022-227b4adcab57
