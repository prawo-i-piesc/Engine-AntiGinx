package main

import (
	parser "Engine-AntiGinx/App/Parameter-Parser"
	"fmt"
	"os"
)

func main() {
	fmt.Println(parser.Parse(os.Args))
}
