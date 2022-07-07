package docker

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"

	"github.com/alecthomas/jsonschema"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/source"

	dockerTypes "github.com/docker/docker/api/types"
	dockerEvents "github.com/docker/docker/api/types/events"
	docker "github.com/moby/docker/client"
)

type PluginConfig struct {
	FlushInterval uint64 `json:"flushInterval" jsonschema:"description=Flush Interval in ms (Default: 30)"`
}

// Plugin represents our plugin
type Plugin struct {
	plugins.BasePlugin
	Config PluginConfig
}

func (p *PluginConfig) Reset() {
	p.FlushInterval = 30
}

// Info displays information of the plugin to Falco plugin framework
func (p *Plugin) Info() *plugins.Info {
	return &plugins.Info{
		ID:          5,
		Name:        "docker",
		Description: "Docker Events",
		Contact:     "github.com/falcosecurity/plugins/",
		Version:     "0.2.0",
		EventSource: "docker",
	}
}

func (p *Plugin) InitSchema() *sdk.SchemaInfo {
	reflector := jsonschema.Reflector{
		// all properties are optional by default
		RequiredFromJSONSchemaTags: true,
		// unrecognized properties don't cause a parsing failures
		AllowAdditionalProperties: true,
	}
	if schema, err := reflector.Reflect(&PluginConfig{}).MarshalJSON(); err == nil {
		return &sdk.SchemaInfo{
			Schema: string(schema),
		}
	}
	return nil
}

// Init is called by the Falco plugin framework as first entry,
// we use it for setting default configuration values and mapping
// values from `init_config` (json format for this plugin)
func (p *Plugin) Init(config string) error {
	p.Config.Reset()
	return json.Unmarshal([]byte(config), &p.Config)
}

// Fields exposes to Falco plugin framework all availables fields for this plugin
func (p *Plugin) Fields() []sdk.FieldEntry {
	return []sdk.FieldEntry{
		{Type: "string", Name: "docker.status", Desc: "Status of the event"},
		{Type: "string", Name: "docker.id", Desc: "ID of the event"},
		{Type: "string", Name: "docker.from", Desc: "From of the event (deprecated)"},
		{Type: "string", Name: "docker.type", Desc: "Type of the event"},
		{Type: "string", Name: "docker.action", Desc: "Action of the event"},
		{Type: "string", Name: "docker.stack.namespace", Desc: "Stack Namespace"},
		{Type: "string", Name: "docker.node.id", Desc: "Swarm Node ID"},
		{Type: "string", Name: "docker.swarm.task", Desc: "Swarm Task"},
		{Type: "string", Name: "docker.swarm.taskid", Desc: "Swarm Task ID"},
		{Type: "string", Name: "docker.swarm.taskname", Desc: "Swarm Task Name"},
		{Type: "string", Name: "docker.swarm.servicename", Desc: "Swarm Service Name"},
		{Type: "string", Name: "docker.node.statenew", Desc: "Node New State"},
		{Type: "string", Name: "docker.node.stateold", Desc: "Node Old State"},
		{Type: "string", Name: "docker.attributes.container", Desc: "Attribute Container"},
		{Type: "string", Name: "docker.attributes.image", Desc: "Attribute Image"},
		{Type: "string", Name: "docker.attributes.name", Desc: "Attribute Name"},
		{Type: "string", Name: "docker.attributes.type", Desc: "Attribute Type"},
		{Type: "string", Name: "docker.attributes.exitcode", Desc: "Attribute Exit Code"},
		{Type: "string", Name: "docker.attributes.signal", Desc: "Attribute Signal"},
		{Type: "string", Name: "docker.scope", Desc: "Scope"},
	}
}

// Extract allows Falco plugin framework to get values for all available fields
func (p *Plugin) Extract(req sdk.ExtractRequest, evt sdk.EventReader) error {
	var data dockerEvents.Message

	rawData, err := ioutil.ReadAll(evt.Reader())
	if err != nil {
		fmt.Println(err.Error())
		return err
	}

	err = json.Unmarshal(rawData, &data)
	if err != nil {
		fmt.Println(err.Error())
		return err
	}

	switch req.Field() {
	case "docker.status":
		req.SetValue(data.Status)
	case "docker.id":
		req.SetValue(data.ID)
	case "docker.from":
		req.SetValue(data.From)
	case "docker.type":
		req.SetValue(data.Type)
	case "docker.action":
		req.SetValue(data.Action)
	case "docker.scope":
		req.SetValue(data.Scope)
	case "docker.actor.id":
		req.SetValue(data.Actor.ID)
	case "docker.stack.namespace":
		req.SetValue(data.Actor.Attributes["com.docker.stack.namespace"])
	case "docker.swarm.task":
		req.SetValue(data.Actor.Attributes["com.docker.swarm.task"])
	case "docker.swarm.taskid":
		req.SetValue(data.Actor.Attributes["com.docker.swarm.task.id"])
	case "docker.swarm.taskname":
		req.SetValue(data.Actor.Attributes["com.docker.swarm.task.name"])
	case "docker.swarm.servicename":
		req.SetValue(data.Actor.Attributes["com.docker.swarm.service.name"])
	case "docker.node.id":
		req.SetValue(data.Actor.Attributes["com.docker.swarm.node.id"])
	case "docker.node.statenew":
		req.SetValue(data.Actor.Attributes["state.new"])
	case "docker.node.stateold":
		req.SetValue(data.Actor.Attributes["state.old"])
	case "docker.attributes.container":
		req.SetValue(data.Actor.Attributes["container"])
	case "docker.attributes.image":
		req.SetValue(data.Actor.Attributes["image"])
	case "docker.attributes.name":
		req.SetValue(data.Actor.Attributes["name"])
	case "docker.attributes.type":
		req.SetValue(data.Actor.Attributes["type"])
	default:
		return fmt.Errorf("no known field: %s", req.Field())
	}

	return nil
}

// Open is called by Falco plugin framework for opening a stream of events, we call that an instance
func (Plugin *Plugin) Open(params string) (source.Instance, error) {
	dclient, err := docker.NewClientWithOpts()
	if err != nil {
		return nil, err
	}

	eventC := make(chan source.PushEvent)
	ctx, cancel := context.WithCancel(context.Background())
	// launch an async worker that listens for Docker events and pushes them
	// to the event channel
	go func() {
		defer close(eventC)
		msgC, errC := dclient.Events(ctx, dockerTypes.EventsOptions{})
		for {
			select {
			case msg, ok := <-msgC:
				if !ok {
					// channel is closed, so we can stop here
					return
				}
				bytes, err := json.Marshal(msg)
				if err != nil {
					eventC <- source.PushEvent{Err: err}
					// errors are blocking, so we can stop here
					return
				}
				eventC <- source.PushEvent{Data: bytes}
			case err, ok := <-errC:
				if !ok {
					// channel is closed, so we can stop here
					return
				}
				if err == io.EOF {
					// map EOF to sdk.ErrEOF, which is recognized by the Go SDK
					err = sdk.ErrEOF
				}
				eventC <- source.PushEvent{Err: err}
				// errors are blocking, so we can stop here
				return
			}
		}
	}()
	return source.NewPushInstance(eventC, source.WithInstanceClose(cancel))
}

// String represents the raw value of on event
// (not currently used by Falco plugin framework, only there for future usage)
func (Plugin *Plugin) String(in io.ReadSeeker) (string, error) {
	evtBytes, err := ioutil.ReadAll(in)
	if err != nil {
		return "", err
	}
	evtStr := string(evtBytes)
	return fmt.Sprintf("%v", evtStr), nil
}
