package server

import (
	"fmt"

	"ewp-core/protocol/ewp"
)

type EWPProtocolHandler struct {
	enableFlow bool
}

func NewEWPProtocolHandler(enableFlow bool) *EWPProtocolHandler {
	return &EWPProtocolHandler{
		enableFlow: enableFlow,
	}
}

func (h *EWPProtocolHandler) Handshake(data []byte, clientIP string) (*HandshakeResult, error) {
	req, respData, err := HandleEWPHandshakeBinary(data, clientIP)
	if err != nil {
		return &HandshakeResult{
			Response: respData,
		}, err
	}

	result := &HandshakeResult{
		Target:   req.TargetAddr.String(),
		Response: respData,
		IsUDP:    req.Command == ewp.CommandUDP,
		UserID:   fmt.Sprintf("%x", req.UUID[:8]),
	}

	if h.enableFlow && !result.IsUDP {
		result.FlowState = ewp.NewFlowState(req.UUID[:])
	}

	return result, nil
}
