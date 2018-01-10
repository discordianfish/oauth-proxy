package e2e

import (
	"bytes"
	"fmt"
	"io/ioutil"
	mathrand "math/rand"
	"net/http"
	"os"
	"testing"
	"time"

	"golang.org/x/net/html"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

func TestOAuthProxyE2E(t *testing.T) {
	ns := os.Getenv("TEST_NAMESPACE")
	oauthProxyTests := map[string]struct {
		oauthProxyArgs []string
		expectedErr    string
	}{
		"basic": {
			oauthProxyArgs: []string{
				"--https-address=:8443",
				"--provider=openshift",
				"--openshift-service-account=proxy",
				"--upstream=http://localhost:8080",
				"--tls-cert=/etc/tls/private/tls.crt",
				"--tls-key=/etc/tls/private/tls.key",
				"--tls-client-ca=/etc/tls/private/ca.crt",
				"--cookie-secret=SECRET",
			},
			expectedErr: "",
		},
		// Tests a scope that is not valid for SA OAuth client use
		"scope-full": {
			oauthProxyArgs: []string{
				"--https-address=:8443",
				"--provider=openshift",
				"--openshift-service-account=proxy",
				"--upstream=http://localhost:8080",
				"--tls-cert=/etc/tls/private/tls.crt",
				"--tls-key=/etc/tls/private/tls.key",
				"--tls-client-ca=/etc/tls/private/ca.crt",
				"--cookie-secret=SECRET",
				"--scope=user:full",
			},
			expectedErr: "403 Permission Denied",
		},
		"sar-ok": {
			oauthProxyArgs: []string{
				"--https-address=:8443",
				"--provider=openshift",
				"--openshift-service-account=proxy",
				"--upstream=http://localhost:8080",
				"--tls-cert=/etc/tls/private/tls.crt",
				"--tls-key=/etc/tls/private/tls.key",
				"--tls-client-ca=/etc/tls/private/ca.crt",
				"--cookie-secret=SECRET",
				`--openshift-sar={"namespace":"` + ns + `","resource":"services","verb":"list"}`,
			},
			expectedErr: "",
		},
		"sar-fail": {
			oauthProxyArgs: []string{
				"--https-address=:8443",
				"--provider=openshift",
				"--openshift-service-account=proxy",
				"--upstream=http://localhost:8080",
				"--tls-cert=/etc/tls/private/tls.crt",
				"--tls-key=/etc/tls/private/tls.key",
				"--tls-client-ca=/etc/tls/private/ca.crt",
				"--cookie-secret=SECRET",
				`--openshift-sar={"namespace":"other","resource":"services","verb":"list"}`,
			},
			expectedErr: "did not reach upstream site",
		},
		"sar-multi-ok": {
			oauthProxyArgs: []string{
				"--https-address=:8443",
				"--provider=openshift",
				"--openshift-service-account=proxy",
				"--upstream=http://localhost:8080",
				"--tls-cert=/etc/tls/private/tls.crt",
				"--tls-key=/etc/tls/private/tls.key",
				"--tls-client-ca=/etc/tls/private/ca.crt",
				"--cookie-secret=SECRET",
				`--openshift-sar=[{"namespace":"` + ns + `","resource":"services","verb":"list"}, {"namespace":"` + ns + `","resource":"routes","verb":"list"}]`,
			},
			expectedErr: "",
		},
		"sar-multi-fail": {
			oauthProxyArgs: []string{
				"--https-address=:8443",
				"--provider=openshift",
				"--openshift-service-account=proxy",
				"--upstream=http://localhost:8080",
				"--tls-cert=/etc/tls/private/tls.crt",
				"--tls-key=/etc/tls/private/tls.key",
				"--tls-client-ca=/etc/tls/private/ca.crt",
				"--cookie-secret=SECRET",
				`--openshift-sar=[{"namespace":"` + ns + `","resource":"services","verb":"list"}, {"namespace":"other","resource":"pods","verb":"list"}]`,
			},
			expectedErr: "did not reach upstream site",
		},
	}

	image := os.Getenv("TEST_IMAGE")

	mathrand.Seed(time.Now().UTC().UnixNano())
	kubeConfig, err := loadConfig(os.Getenv("KUBECONFIG"), os.Getenv("KUBECONTEXT"))
	if err != nil {
		t.Fatalf("error loading kubeconfig: '%s', ctx: '%s', err: %s", os.Getenv("KUBECONFIG"), os.Getenv("KUBECONTEXT"), err)
	}
	kubeClientSet, err := kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		t.Fatalf("error generating kube client: %s", err)
	}

	t.Logf("test image: %s, test namespace: %s", image, ns)

	for tcName, tc := range oauthProxyTests {
		t.Run(fmt.Sprintf("setting up e2e tests %s", tcName), func(t *testing.T) {
			_, err := kubeClientSet.CoreV1().ServiceAccounts(ns).Create(newOAuthProxySA())
			if err != nil {
				t.Fatalf("setup: error creating SA: %s", err)
			}

			err = newOAuthProxyRoute()
			if err != nil {
				t.Fatalf("setup: error creating route: %s", err)
			}

			// Find the exposed route hostname that we will be doing client actions against
			proxyRouteHost, err := getRouteHost("proxy-route", ns)
			if err != nil {
				t.Fatalf("setup: error finding route host: %s", err)
			}

			// Create the TLS certificate set for the client and service (with the route hostname attributes)
			caPem, serviceCert, serviceKey, err := createCAandCertSet(proxyRouteHost)
			if err != nil {
				t.Fatalf("setup: error creating TLS certs: %s", err)
			}

			_, err = kubeClientSet.CoreV1().Services(ns).Create(newOAuthProxyService())
			if err != nil {
				t.Fatalf("setup: error creating service: %s", err)
			}

			// configMap provides oauth-proxy with the certificates we created above
			_, err = kubeClientSet.CoreV1().ConfigMaps(ns).Create(newOAuthProxyConfigMap(ns, caPem, serviceCert, serviceKey))
			if err != nil {
				t.Fatalf("setup: error creating certificate configMap: %s", err)
			}

			oauthProxyPod, err := kubeClientSet.CoreV1().Pods(ns).Create(newOAuthProxyPod(image, tc.oauthProxyArgs))
			if err != nil {
				t.Fatalf("setup: error creating oauth-proxy pod with image '%s' and args '%v': %s", image, tc.oauthProxyArgs, err)
			}

			err = waitForPodRunningInNamespace(kubeClientSet, oauthProxyPod)
			if err != nil {
				t.Fatalf("setup: error waiting for pod to run: %s", err)
			}

			// Find the service CA for the client trust store
			secrets, err := kubeClientSet.CoreV1().Secrets(ns).List(metav1.ListOptions{})
			if err != nil {
				t.Fatalf("setup: error listing secrets: %s", err)
			}

			var openshiftPemCA []byte
			for _, s := range secrets.Items {
				cert, ok := s.Data["ca.crt"]
				if !ok {
					continue
				}
				openshiftPemCA = cert
				break
			}
			if openshiftPemCA == nil {
				t.Fatalf("setup: could not find openshift CA from secrets")
			}

			host := "https://" + proxyRouteHost + "/oauth/start"
			// Wait for the route, we get an EOF if we move along too fast
			err = waitUntilRouteIsReady([][]byte{caPem, openshiftPemCA}, host)
			if err != nil {
				t.Fatalf("setup: error waiting for route availability: %s", err)
			}

			user := randLogin()
			// For SAR tests the random user needs the admin role for this namespace.
			out, err := execCmd("oc", []string{"adm", "policy", "add-role-to-user", "admin", user}, "")
			if err != nil {
				t.Fatalf("setup: error setting test user role: %s", err)
			}
			t.Logf("%s", out)

			defer func() {
				if os.Getenv("DEBUG_TEST") == tcName {
					t.Fatalf("skipping cleanup step for test '%s' and stopping on command", tcName)
				}
				t.Logf("cleaning up test %s", tcName)
				kubeClientSet.CoreV1().Pods(ns).Delete("proxy", nil)
				kubeClientSet.CoreV1().Services(ns).Delete("proxy", nil)
				deleteTestRoute("proxy-route")
				kubeClientSet.CoreV1().ConfigMaps(ns).Delete("proxy-certs", nil)
				kubeClientSet.CoreV1().ServiceAccounts(ns).Delete("proxy", nil)
				waitForPodDeletion(kubeClientSet, oauthProxyPod.Name, ns)
				execCmd("oc", []string{"adm", "policy", "remove-role-from-user", "admin", user}, "")
			}()

			t.Logf("running e2e test %s", tcName)
			err = confirmOAuthFlow(proxyRouteHost, [][]byte{caPem, openshiftPemCA}, user, tc.expectedErr)

			if err == nil && len(tc.expectedErr) > 0 {
				t.Errorf("expected error '%s', but test passed", tc.expectedErr)
			}

			if err != nil {
				if len(tc.expectedErr) > 0 {
					if tc.expectedErr != err.Error() {
						t.Errorf("expected error '%s', got '%s'", tc.expectedErr, err)
					}
				} else {
					t.Errorf("test failed with '%s'", err)
				}
			}
		})
	}
}

func submitOAuthForm(client *http.Client, response *http.Response, user, expectedErr string) (*http.Response, error) {
	responseBytes, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	responseBuffer := bytes.NewBuffer(responseBytes)

	body, err := html.Parse(responseBuffer)
	if err != nil {
		return nil, err
	}

	forms := getElementsByTagName(body, "form")
	if len(forms) != 1 {
		errMsg := "expected OpenShift form"
		// Return the expected error if it's found amongst the text elements
		if expectedErr != "" {
			checkBuffer := bytes.NewBuffer(responseBytes)
			parsed, err := html.Parse(checkBuffer)
			if err != nil {
				return nil, err
			}

			textNodes := getTextNodes(parsed)
			for i := range textNodes {
				if textNodes[i].Data == expectedErr {
					errMsg = expectedErr
				}
			}
		}
		return nil, fmt.Errorf(errMsg)
	}

	formReq, err := newRequestFromForm(forms[0], response.Request.URL, user)
	if err != nil {
		return nil, err
	}

	postResp, err := client.Do(formReq)
	if err != nil {
		return nil, err
	}

	return postResp, nil
}

func confirmOAuthFlow(host string, cas [][]byte, user, expectedErr string) error {
	// Set up the client cert store
	client, err := newHTTPSClient(cas)
	if err != nil {
		return err
	}

	// Go straight to start, redirecting to OpenShift login
	startUrl := "https://" + host + "/oauth/start"
	resp, err := getResponse(startUrl, client)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// OpenShift login
	loginResp, err := submitOAuthForm(client, resp, user, expectedErr)
	if err != nil {
		return err
	}
	defer loginResp.Body.Close()

	// authorization grant form
	grantResp, err := submitOAuthForm(client, loginResp, user, expectedErr)
	if err != nil {
		return err
	}
	defer grantResp.Body.Close()

	accessRespBody, err := ioutil.ReadAll(grantResp.Body)
	if err != nil {
		return nil
	}

	if string(accessRespBody) != "Hello OpenShift!\n" {
		return fmt.Errorf("did not reach upstream site")
	}

	return nil
}
