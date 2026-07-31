package rest

import (
	"log"
	"net"
	"net/http"

	"github.com/pooyahpx/HPXNODE/common"
)

func (s *Service) Base(w http.ResponseWriter, _ *http.Request) {
	common.SendProtoResponse(w, s.BaseInfoResponse())
}

func (s *Service) Start(w http.ResponseWriter, r *http.Request) {
	data := &common.Backend{}

	if err := common.ReadProtoBody(r.Body, data); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		http.Error(w, "unknown ip", http.StatusServiceUnavailable)
		return
	}

	// Same client -> add another core to the node; different client -> take over.
	existing := s.Backend() != nil
	sameClient := existing && s.Ip() == ip

	if existing && !sameClient {
		log.Println("New connection from ", ip, " core control access was taken away from previous client.")
		s.Disconnect()
	}

	if err = s.StartBackend(r.Context(), data); err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	if sameClient {
		s.NewRequest()
	} else {
		s.Connect(ip, data.GetKeepAlive())
	}

	common.SendProtoResponse(w, s.BaseInfoResponse())
}

func (s *Service) Stop(w http.ResponseWriter, _ *http.Request) {
	s.Disconnect()

	common.SendProtoResponse(w, &common.Empty{})
}
