//go:build tools

package tools

// Keeps golang.org/x/mobile in go.mod so `gomobile bind` can resolve its bind package.
import _ "golang.org/x/mobile/bind"
