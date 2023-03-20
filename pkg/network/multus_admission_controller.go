package network

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	securityv1 "github.com/openshift/api/security/v1"
	hyperv1 "github.com/openshift/hypershift/api/v1alpha1"
	"github.com/pkg/errors"

	"github.com/openshift/cluster-network-operator/pkg/bootstrap"
	cnoclient "github.com/openshift/cluster-network-operator/pkg/client"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/discovery"

	"github.com/openshift/cluster-network-operator/pkg/names"
	"github.com/openshift/cluster-network-operator/pkg/render"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	uns "k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/klog/v2"
)

// ignoredNamespaces contains the comma separated namespace list that should be ignored
// to watch by multus admission controller. This only initialized first invocation.
var ignoredNamespaces string

// getOpenshiftNamespaces collect openshift related namespaces, as comma separate list
func getOpenshiftNamespaces(client cnoclient.Client) (string, error) {
	namespaces := []string{}

	// get openshift specific namespaces to add them into ignoreNamespace
	nsList, err := client.Default().Kubernetes().CoreV1().Namespaces().List(context.TODO(), metav1.ListOptions{
		LabelSelector: "openshift.io/cluster-monitoring==true",
	})
	if err != nil {
		return "", errors.Wrap(err, "failed to get namespaces to render multus admission controller manifests")
	}

	for _, ns := range nsList.Items {
		namespaces = append(namespaces, ns.Name)
	}
	return strings.Join(namespaces, ","), nil
}

// renderMultusAdmissonControllerConfig returns the manifests of Multus Admisson Controller
func renderMultusAdmissonControllerConfig(manifestDir string, externalControlPlane bool, bootstrapResult *bootstrap.BootstrapResult, client cnoclient.Client) ([]*uns.Unstructured, error) {
	//sccSupported, err1 := isSccSupported(client.Default().RESTMapper().Kubernetes().Discovery()) // kubeDiscoveryClient

	objs := []*uns.Unstructured{}
	var err error

	replicas := getMultusAdmissionControllerReplicas(bootstrapResult)
	if ignoredNamespaces == "" {
		ignoredNamespaces, err = getOpenshiftNamespaces(client)
		if err != nil {
			klog.Warningf("failed to get openshift namespaces: %+v", err)
		}
	}

	// render the manifests on disk
	data := render.MakeRenderData()
	data.Data["ReleaseVersion"] = os.Getenv("RELEASE_VERSION")
	data.Data["MultusAdmissionControllerImage"] = os.Getenv("MULTUS_ADMISSION_CONTROLLER_IMAGE")
	data.Data["IgnoredNamespace"] = ignoredNamespaces
	data.Data["MultusValidatingWebhookName"] = names.MULTUS_VALIDATING_WEBHOOK
	data.Data["KubeRBACProxyImage"] = os.Getenv("KUBE_RBAC_PROXY_IMAGE")
	data.Data["ExternalControlPlane"] = externalControlPlane
	data.Data["Replicas"] = replicas
	// Hypershift
	hsc := NewHyperShiftConfig()
	data.Data["HyperShiftEnabled"] = hsc.Enabled
	data.Data["ManagementClusterName"] = names.ManagementClusterName
	data.Data["AdmissionControllerNamespace"] = "openshift-multus"
	data.Data["RHOBSMonitoring"] = os.Getenv("RHOBS_MONITORING")
	if hsc.Enabled {
		data.Data["AdmissionControllerNamespace"] = hsc.Namespace
		data.Data["KubernetesServiceHost"] = bootstrapResult.Infra.APIServers[bootstrap.APIServerDefaultLocal].Host
		data.Data["KubernetesServicePort"] = bootstrapResult.Infra.APIServers[bootstrap.APIServerDefaultLocal].Port
		data.Data["CLIImage"] = os.Getenv("CLI_IMAGE")
		data.Data["TokenMinterImage"] = os.Getenv("TOKEN_MINTER_IMAGE")
		data.Data["TokenAudience"] = os.Getenv("TOKEN_AUDIENCE")

		// Get serving CA from the management cluster since the service resides there
		serviceCA := &corev1.ConfigMap{}
		err := client.ClientFor(names.ManagementClusterName).CRClient().Get(
			context.TODO(), types.NamespacedName{Namespace: hsc.Namespace, Name: "openshift-service-ca.crt"}, serviceCA)
		if err != nil {
			return nil, fmt.Errorf("failed to get managments clusters service CA: %v", err)
		}
		ca, exists := serviceCA.Data["service-ca.crt"]
		if !exists {
			return nil, fmt.Errorf("(%s) %s/%s missing 'service-ca.crt' key", serviceCA.GroupVersionKind(), serviceCA.Namespace, serviceCA.Name)
		}

		data.Data["ManagementServiceCABundle"] = base64.URLEncoding.EncodeToString([]byte(ca))

		hcp := &hyperv1.HostedControlPlane{ObjectMeta: metav1.ObjectMeta{Name: hsc.Name}}
		err = client.ClientFor(names.ManagementClusterName).CRClient().Get(context.TODO(), types.NamespacedName{Namespace: hsc.Namespace, Name: hsc.Name}, hcp)
		if err != nil {
			return nil, fmt.Errorf("failed to get hosted controlplane: %v", err)
		}
		data.Data["ClusterIDLabel"] = ClusterIDLabel
		data.Data["ClusterID"] = hcp.Spec.ClusterID
	}

	manifests, err := render.RenderDir(filepath.Join(manifestDir, "network/multus-admission-controller"), &data)
	if err != nil {
		return nil, errors.Wrap(err, "failed to render multus admission controller manifests")
	}
	objs = append(objs, manifests...)
	return objs, nil
}

func isSccSupported(client discovery.ServerResourcesInterface) (bool, error) {
	// check for scc capability
	hasSccCap, err := isAPIResourceRegistered(client, securityv1.GroupVersion, "securitycontextconstraints")
	if err != nil {
		return false, err
	}

	return hasSccCap, nil
}

// isAPIResourceRegistered determines if a specified API resource is registered on the cluster
func isAPIResourceRegistered(client discovery.ServerResourcesInterface, groupVersion schema.GroupVersion, resourceName string) (bool, error) {
	apis, err := client.ServerResourcesForGroupVersion(groupVersion.String())
	if err != nil && !apierrors.IsNotFound(err) {
		return false, err
	}

	if apis != nil {
		for _, api := range apis.APIResources {
			if api.Name == resourceName || api.SingularName == resourceName {
				return true, nil
			}
		}
	}

	return false, nil
}

// IsNotFound returns true if the specified error was created by NewNotFound.
// It supports wrapped errors and returns false when the error is nil.
func IsNotFound(err error) bool {
	reason, code := reasonAndCodeForError(err)
	if reason == metav1.StatusReasonNotFound || code == http.StatusNotFound {
		return true
	}
	return false
}

func reasonAndCodeForError(err error) (metav1.StatusReason, int32) {
	if status, ok := err.(APIStatus); ok || errors.As(err, &status) {
		return status.Status().Reason, status.Status().Code
	}
	return metav1.StatusReasonUnknown, 0
}

// APIStatus is exposed by errors that can be converted to an api.Status object
// for finer grained details.
type APIStatus interface {
	Status() metav1.Status
}
