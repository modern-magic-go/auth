module github.com/modern-magic-go/auth/testdata/interop

go 1.21

require (
	github.com/golang-jwt/jwt/v4 v4.5.2
	github.com/modern-magic-go/auth v0.0.0
)

replace github.com/modern-magic-go/auth => ../..
