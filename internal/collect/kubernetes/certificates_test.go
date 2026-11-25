package kubernetes

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	k8stesting "k8s.io/client-go/testing"
)

// newCertDynClient builds a fake dynamic client that knows how to List the
// cert-manager Certificate GVR (required so the fake doesn't panic on List),
// then overrides that List with a reactor returning listErr, or, if listErr is
// nil, serving whatever objects are passed in.
func newCertDynClient(listErr error) *dynamicfake.FakeDynamicClient {
	scheme := runtime.NewScheme()
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(scheme,
		map[schema.GroupVersionResource]string{certGVR: "CertificateList"})
	if listErr != nil {
		dyn.PrependReactor("list", "certificates", func(k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, listErr
		})
	}
	return dyn
}

// A Forbidden error is what a reader ClusterRole without cert-manager.io
// access produces (e.g. a read-only role scoped to core resources). It must
// be classified as a coverage gap (isPermissionError, client.go) through the
// %w wrap collectCertManagerCerts applies — NOT surfaced in a way that forces
// every k8s sweep permanently Partial.
func TestCollectCertManagerCerts_Forbidden_IsPermissionError(t *testing.T) {
	forbidden := apierrors.NewForbidden(
		schema.GroupResource{Group: "cert-manager.io", Resource: "certificates"}, "", errors.New("nope"))
	dyn := newCertDynClient(forbidden)

	assets, edges, err := collectCertManagerCerts(context.Background(), dyn, "c1", time.Now())
	require.Error(t, err, "a Forbidden must still be returned as an error to the caller")
	require.Nil(t, assets)
	require.Nil(t, edges)
	require.True(t, apierrors.IsForbidden(err),
		"apierrors.IsForbidden must see through collectCertManagerCerts' %%w wrap")
	require.True(t, isPermissionError(err),
		"the call site in Collect must be able to carve this out of Partial")
}

// A transient failure (timeout, 500) must NOT be classified as a permission
// error — Collect still needs to flag Partial on it.
func TestCollectCertManagerCerts_Transient_IsNotPermissionError(t *testing.T) {
	transientErr := errors.New("dial tcp: i/o timeout")
	dyn := newCertDynClient(transientErr)

	assets, edges, err := collectCertManagerCerts(context.Background(), dyn, "c1", time.Now())
	require.Error(t, err)
	require.Nil(t, assets)
	require.Nil(t, edges)
	require.False(t, isPermissionError(err),
		"a transient error must still flag Partial at the call site")
}

// A genuinely absent CRD (cert-manager not installed) must be silently skipped:
// no error, no assets, no edges — and specifically must NOT be classified as a
// permission error (it isn't one).
func TestCollectCertManagerCerts_CRDAbsent_NoErrorNoPartial(t *testing.T) {
	notFound := apierrors.NewGenericServerResponse(404, "list",
		schema.GroupResource{Group: "cert-manager.io", Resource: "certificates"}, "", "", 0, false)
	dyn := newCertDynClient(notFound)

	assets, edges, err := collectCertManagerCerts(context.Background(), dyn, "c1", time.Now())
	require.NoError(t, err, "a CRD-absent cluster is not an error condition")
	require.Nil(t, assets)
	require.Nil(t, edges)
}

// collectCertManagerCerts must still map actual Certificate objects when the
// list succeeds — a sanity check that the reactor plumbing above isn't masking
// a broken happy path.
func TestCollectCertManagerCerts_HappyPath(t *testing.T) {
	dyn := newCertDynClient(nil)
	obj := map[string]interface{}{
		"apiVersion": "cert-manager.io/v1",
		"kind":       "Certificate",
		"metadata": map[string]interface{}{
			"name":      "web-tls",
			"namespace": "app",
		},
		"spec": map[string]interface{}{
			"secretName": "web-tls-secret",
			"dnsNames":   []interface{}{"example.com"},
		},
	}
	_, err := dyn.Resource(certGVR).Namespace("app").Create(context.Background(),
		&unstructured.Unstructured{Object: obj}, metav1.CreateOptions{})
	require.NoError(t, err)

	assets, edges, err := collectCertManagerCerts(context.Background(), dyn, "c1", time.Now())
	require.NoError(t, err)
	require.Len(t, assets, 1)
	require.Equal(t, "c1/certificate/app/web-tls", assets[0].ID)
	require.Len(t, edges, 1)
}

// A Collect()-level integration test against the real *realK8s cert-manager
// path (rather than only the extracted collectCertManagerCerts helper above)
// is not possible without changing client.go: realK8s.cs is a concrete
// *kubernetes.Clientset, not an interface, so a fake typed clientset cannot be
// substituted in from this package's tests. The call-site logic in Collect (kubernetes.go) that gates
// result.Partial on the cert-manager error is a single line —
// `result.Partial = result.Partial || !isPermissionError(err)` — identical in
// shape to the already-covered ListRoles/ListRoleBindings sites
// (TestCollect_MissingRBACPermissionIsNotPartial /
// TestCollect_TransientRBACErrorIsPartial below), and isPermissionError's
// classification of the exact errors collectCertManagerCerts returns is
// pinned by the three tests above.
