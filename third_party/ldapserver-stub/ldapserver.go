// Package ldapserver is an inert, API-compatible stand-in for
// github.com/projectdiscovery/ldapserver (GPL-2.0), substituted via a
// `replace` directive in the root go.mod. Written from scratch against the
// call sites in github.com/projectdiscovery/interactsh/pkg/server (MIT); it
// contains no code from the GPL module.
//
// Why: nuclei's output package imports interactsh/pkg/server for one struct
// type (server.Interaction), which transitively compiles in interactsh's
// LDAP callback *server*. Vulngraph never runs an interactsh server — it only
// embeds nuclei as a scan engine — so the LDAP listener is dead code here,
// but linking it would put GPL-2.0 code in every binary and image.
//
// Every operation is a no-op and ListenAndServe always fails, so if anything
// ever did try to start the LDAP listener it fails loudly instead of silently
// doing something. See README.md for how to verify the substitution holds.
package ldapserver

import (
	"errors"
	"net"

	"github.com/lor00x/goldap/message"
)

// ErrDisabled is returned by every operation that would start serving.
var ErrDisabled = errors.New("ldapserver: LDAP server support is not compiled into this build")

// LDAP result codes and OIDs referenced by callers.
const (
	LDAPResultSuccess                   = message.ResultCodeSuccess
	LDAPResultOperationsError           = message.ResultCodeOperationsError
	LDAPResultCompareTrue               = message.ResultCodeCompareTrue
	LDAPResultUnwillingToPerform        = message.ResultCodeUnwillingToPerform
	NoticeOfStartTLS                    = message.LDAPOID("1.3.6.1.4.1.1466.20037")
	NoticeOfWhoAmI                      = message.LDAPOID("1.3.6.1.4.1.4203.1.11.3")
	ApplicationBindRequest              = message.TagBindRequest
	ModifyRequestChangeOperationAdd     = 0
	ModifyRequestChangeOperationDelete  = 1
	ModifyRequestChangeOperationReplace = 2
)

// HandleLogCallback mirrors the upstream logging hook; never invoked here.
var HandleLogCallback func(hostname string, format string, v ...interface{})

// ResponseWriter receives protocol responses.
type ResponseWriter interface {
	Write(po interface{})
}

// HandlerFunc handles one request.
type HandlerFunc func(ResponseWriter, *Message)

// Client is the connection a Message arrived on.
type Client struct{ conn net.Conn }

func (c *Client) Addr() net.Addr {
	if c == nil || c.conn == nil {
		return &net.TCPAddr{}
	}
	return c.conn.RemoteAddr()
}
func (c *Client) GetConn() net.Conn                   { return c.conn }
func (c *Client) SetConn(conn net.Conn)               { c.conn = conn }
func (c *Client) GetMessageByID(int) (*Message, bool) { return nil, false }

// Message is one decoded LDAP request.
type Message struct {
	Client *Client
}

func (m *Message) Abandon()                                  {}
func (m *Message) String() string                            { return "" }
func (m *Message) ProtocolOpType() int                       { return -1 }
func (m *Message) GetAbandonRequest() message.AbandonRequest { return 0 }
func (m *Message) GetAddRequest() message.AddRequest         { return message.AddRequest{} }
func (m *Message) GetBindRequest() message.BindRequest       { return message.BindRequest{} }
func (m *Message) GetCompareRequest() message.CompareRequest { return message.CompareRequest{} }
func (m *Message) GetDeleteRequest() message.DelRequest      { return message.DelRequest("") }
func (m *Message) GetExtendedRequest() message.ExtendedRequest {
	return message.ExtendedRequest{}
}
func (m *Message) GetModifyRequest() message.ModifyRequest { return message.ModifyRequest{} }
func (m *Message) GetSearchRequest() message.SearchRequest { return message.SearchRequest{} }

// Response constructors.
func NewResponse(code int) message.LDAPResult {
	var r message.LDAPResult
	r.SetResultCode(code)
	return r
}
func NewBindResponse(code int) message.BindResponse {
	var r message.BindResponse
	r.SetResultCode(code)
	return r
}
func NewExtendedResponse(code int) message.ExtendedResponse {
	var r message.ExtendedResponse
	r.SetResultCode(code)
	return r
}
func NewSearchResultDoneResponse(code int) message.SearchResultDone {
	var r message.SearchResultDone
	r.SetResultCode(code)
	return r
}
func NewModifyResponse(code int) message.ModifyResponse {
	var r message.ModifyResponse
	r.SetResultCode(code)
	return r
}
func NewAddResponse(code int) message.AddResponse {
	var r message.AddResponse
	r.SetResultCode(code)
	return r
}
func NewDeleteResponse(code int) message.DelResponse {
	var r message.DelResponse
	r.SetResultCode(code)
	return r
}
func NewCompareResponse(code int) message.CompareResponse {
	var r message.CompareResponse
	r.SetResultCode(code)
	return r
}

// SearchResultEntry is a search hit under construction.
type SearchResultEntry struct{}

func NewSearchResultEntry(string) *SearchResultEntry                    { return &SearchResultEntry{} }
func (e *SearchResultEntry) AddAttribute(name string, values ...string) {}

// Route is one registered handler.
type Route struct{}

func (r *Route) RequestName(message.LDAPOID) *Route { return r }
func (r *Route) Label(string) *Route                { return r }

// RouteMux dispatches requests to handlers.
type RouteMux struct{}

func NewRouteMux() *RouteMux                  { return &RouteMux{} }
func (*RouteMux) Bind(HandlerFunc) *Route     { return &Route{} }
func (*RouteMux) NotFound(HandlerFunc)        {}
func (*RouteMux) Abandon(HandlerFunc) *Route  { return &Route{} }
func (*RouteMux) Compare(HandlerFunc) *Route  { return &Route{} }
func (*RouteMux) Add(HandlerFunc) *Route      { return &Route{} }
func (*RouteMux) Delete(HandlerFunc) *Route   { return &Route{} }
func (*RouteMux) Modify(HandlerFunc) *Route   { return &Route{} }
func (*RouteMux) Extended(HandlerFunc) *Route { return &Route{} }
func (*RouteMux) Search(HandlerFunc) *Route   { return &Route{} }

// Server would listen for LDAP connections; here it never does.
type Server struct {
	Listener net.Listener
}

func NewServer() *Server                                      { return &Server{Listener: closedListener{}} }
func (*Server) Handle(*RouteMux) error                        { return nil }
func (*Server) ListenAndServe(string, ...func(*Server)) error { return ErrDisabled }

type closedListener struct{}

func (closedListener) Accept() (net.Conn, error) { return nil, ErrDisabled }
func (closedListener) Close() error              { return nil }
func (closedListener) Addr() net.Addr            { return &net.TCPAddr{} }
