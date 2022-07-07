package main

import (
	docker "github.com/Issif/docker-plugin/pkg"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/extractor"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/source"
)

func init() {
	plugins.SetFactory(func() plugins.Plugin {
		p := &docker.Plugin{}
		extractor.Register(p)
		source.Register(p)
		return p
	})
}

func main() {}
