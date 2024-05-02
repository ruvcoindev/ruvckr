package restapi

import (
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"

	c "github.com/ruvcoindev/ruvchain-go/src/config"
	d "github.com/ruvcoindev/ruvchain-go/src/defaults"
	"github.com/ruvcoindev/ruvchain-go/src/restapi"
	"github.com/ruvcoindev/ruvckr/src/config"
)

type RestServer struct {
	server *restapi.RestServer
	config *c.NodeConfig
}

func NewRestServer(server *restapi.RestServer, cfg *c.NodeConfig) (*restapi.RestServer, error) {
	a := &RestServer{
		server,
		cfg,
	}
	//add CKR for REST handlers here
	a.server.AddHandler(restapi.ApiHandler{Method: "GET", Pattern: "/api/tunnelrouting", Desc: "Show TunnelRouting settings", Handler: a.getApiTunnelRouting})
	a.server.AddHandler(restapi.ApiHandler{Method: "PUT", Pattern: "/api/tunnelrouting", Desc: "Set TunnelRouting settings", Handler: a.putApiTunnelRouting})
	return a.server, nil
}

// @Summary		Show TunnelRouting settings.
// @Produce		json
// @Success		200		{string}	string		"ok"
// @Failure		400		{error}		error		"Method not allowed"
// @Failure		401		{error}		error		"Authentication failed"
// @Router		/tunnelrouting [get]
func (a *RestServer) getApiTunnelRouting(w http.ResponseWriter, r *http.Request) {
	restapi.WriteJson(w, r, a.config.FeaturesConfig["TunnelRouting"])
}

// @Summary		Set TunnelRouting settings.
// @Produce		json
// @Success		204		{string}	string		"No content"
// @Failure		400		{error}		error		"Bad request"
// @Failure		401		{error}		error		"Authentication failed"
// @Failure		500		{error}		error		"Internal error"
// @Router		/tunnelrouting [put]
func (a *RestServer) putApiTunnelRouting(w http.ResponseWriter, r *http.Request) {
	var tunnelRouting config.TunnelRoutingConfig
	err := json.NewDecoder(r.Body).Decode(&tunnelRouting)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if tunnelRouting.Enable {
		if tunnelRouting.IPv4RemoteSubnets == nil && tunnelRouting.IPv6RemoteSubnets == nil {
			http.Error(w, "IPv4RemoteSubnets and IPv6RemoteSubnets parameters are missing", http.StatusBadRequest)
			return
		}
		if tunnelRouting.IPv4RemoteSubnets != nil {
			for subnet, value := range tunnelRouting.IPv4RemoteSubnets {
				if value == "" {
					http.Error(w, "Public key is missing", http.StatusBadRequest)
					return
				}
				_, _, err := net.ParseCIDR(subnet)
				if err != nil {
					http.Error(w, "IPv4 subnetwork is invalid", http.StatusBadRequest)
					return
				}
				data, err := hex.DecodeString(value)
				if err != nil || len(data) != 32 {
					http.Error(w, "Public key is invalid", http.StatusBadRequest)
					return
				}
			}
		}
		if tunnelRouting.IPv6RemoteSubnets != nil {
			for subnet, value := range tunnelRouting.IPv6RemoteSubnets {
				if value == "" {
					http.Error(w, "Public key is missing", http.StatusBadRequest)
					return
				}
				_, _, err := net.ParseCIDR(subnet)
				if err != nil {
					http.Error(w, "IPv6 subnetwork is invalid", http.StatusBadRequest)
					return
				}
				data, err := hex.DecodeString(value)
				if err != nil || len(data) != 32 {
					http.Error(w, "Public key is invalid", http.StatusBadRequest)
					return
				}
			}
		}
	}
	w.WriteHeader(http.StatusNoContent)
	a.saveConfig(func(cfg *c.NodeConfig) {
		cfg.FeaturesConfig["TunnelRouting"] = tunnelRouting
	}, r)
}

func (a *RestServer) saveConfig(setConfigFields func(*c.NodeConfig), r *http.Request) {
	if len(a.server.ConfigFn) > 0 {
		saveHeaders := r.Header["Ruv-Save-Config"]
		if len(saveHeaders) > 0 && saveHeaders[0] == "true" {
			cfg, err := d.ReadConfig(a.server.ConfigFn)
			if err == nil {
				if setConfigFields != nil {
					setConfigFields(cfg)
				}
				err := d.WriteConfig(a.server.ConfigFn, cfg)
				if err != nil {
					a.server.Log.Errorln("Config file write error:", err)
				}
			} else {
				a.server.Log.Errorln("Config file read error:", err)
			}
		}
	}
}

func (a *RestServer) Serve() error {
	return a.server.Serve()
}
