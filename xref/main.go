package main

import (
	"flag"
	"fmt"
	"go/build"
	"strings"

	"github.com/golang/glog"
	"golang.org/x/tools/refactor/importgraph"
)

var (
	fromPrefix = flag.String("from", "github.com/google", "Prefix of importing package")
	toPrefix   = flag.String("to", "github.com/google", "Prefix of imported package")
)

func main() {
	flag.Parse()
	fwd, _, errs := importgraph.Build(&build.Default)
	if len(errs) > 0 {
		glog.Exitf("errors %v", errs)
	}

	for from, toSet := range fwd {
		if !strings.HasPrefix(from, *fromPrefix) {
			continue
		}
		for to := range toSet {
			if !strings.HasPrefix(to, *toPrefix) {
				continue
			}
			fmt.Printf("%s -> %s\n", from, to)
		}
	}
}
