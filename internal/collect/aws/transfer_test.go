package aws

import (
	"context"
	"errors"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/transfer"
	transfertypes "github.com/aws/aws-sdk-go-v2/service/transfer/types"
	"github.com/stretchr/testify/require"
)

type fakeTransfer struct {
	servers     []*transfer.ListServersOutput
	serverCalls int
	described   map[string]*transfertypes.DescribedServer
	connectors  *transfer.ListConnectorsOutput
	connErr     error
	conns       map[string]*transfertypes.DescribedConnector
}

func (f *fakeTransfer) ListServers(_ context.Context, _ *transfer.ListServersInput, _ ...func(*transfer.Options)) (*transfer.ListServersOutput, error) {
	p := f.servers[f.serverCalls]
	f.serverCalls++
	return p, nil
}

func (f *fakeTransfer) DescribeServer(_ context.Context, in *transfer.DescribeServerInput, _ ...func(*transfer.Options)) (*transfer.DescribeServerOutput, error) {
	s, ok := f.described[awssdk.ToString(in.ServerId)]
	if !ok {
		return nil, errors.New("AccessDeniedException")
	}
	return &transfer.DescribeServerOutput{Server: s}, nil
}

func (f *fakeTransfer) ListConnectors(_ context.Context, _ *transfer.ListConnectorsInput, _ ...func(*transfer.Options)) (*transfer.ListConnectorsOutput, error) {
	if f.connErr != nil {
		return nil, f.connErr
	}
	return f.connectors, nil
}

func (f *fakeTransfer) DescribeConnector(_ context.Context, in *transfer.DescribeConnectorInput, _ ...func(*transfer.Options)) (*transfer.DescribeConnectorOutput, error) {
	c, ok := f.conns[awssdk.ToString(in.ConnectorId)]
	if !ok {
		return nil, errors.New("AccessDeniedException")
	}
	return &transfer.DescribeConnectorOutput{Connector: c}, nil
}

func TestReadTransfer(t *testing.T) {
	client := &fakeTransfer{
		servers: []*transfer.ListServersOutput{
			{Servers: []transfertypes.ListedServer{{Arn: awssdk.String("arn:s-ftp"), ServerId: awssdk.String("s-ftp")}}, NextToken: awssdk.String("p2")},
			{Servers: []transfertypes.ListedServer{{Arn: awssdk.String("arn:s-sftp"), ServerId: awssdk.String("s-sftp")}, {Arn: awssdk.String("arn:s-denied"), ServerId: awssdk.String("s-denied")}}},
		},
		described: map[string]*transfertypes.DescribedServer{
			"s-ftp":  {Protocols: []transfertypes.Protocol{transfertypes.ProtocolSftp, transfertypes.ProtocolFtp}},
			"s-sftp": {Protocols: []transfertypes.Protocol{transfertypes.ProtocolSftp}},
		},
		connectors: &transfer.ListConnectorsOutput{Connectors: []transfertypes.ListedConnector{
			{Arn: awssdk.String("arn:c-log"), ConnectorId: awssdk.String("c-log")},
			{Arn: awssdk.String("arn:c-nolog"), ConnectorId: awssdk.String("c-nolog")},
			{Arn: awssdk.String("arn:c-denied"), ConnectorId: awssdk.String("c-denied")},
		}},
		conns: map[string]*transfertypes.DescribedConnector{
			"c-log":   {LoggingRole: awssdk.String("arn:aws:iam::1:role/log")},
			"c-nolog": {},
		},
	}
	got, err := readTransfer(context.Background(), client, "us-east-1", "1", time.Now())
	require.NoError(t, err)
	m := indexAssetsByID(got)
	require.Len(t, m, 6)
	require.Equal(t, "true", m["arn:s-ftp"].Metadata["ftp_enabled"])
	require.Equal(t, "SFTP,FTP", m["arn:s-ftp"].Metadata["protocols"])
	require.Equal(t, "false", m["arn:s-sftp"].Metadata["ftp_enabled"])
	require.NotContains(t, m["arn:s-denied"].Metadata, "ftp_enabled", "an unread server is emitted with its protocols unknown")
	require.Equal(t, "arn:aws:iam::1:role/log", m["arn:c-log"].Metadata["logging_role"])
	v, ok := m["arn:c-nolog"].Metadata["logging_role"]
	require.True(t, ok)
	require.Empty(t, v, "no logging role is observed as empty")
	require.NotContains(t, m["arn:c-denied"].Metadata, "logging_role")

	client.serverCalls = 0
	client.connErr = errors.New("throttled")
	_, err = readTransfer(context.Background(), client, "us-east-1", "1", time.Now())
	require.Error(t, err, "a failed connector listing fails the service rather than reading as no connectors")
}
