FROM rhel7:7-released

RUN yum-config-manager --enable rhel-7-server-ose-3.10-rpms && \
    yum install -y golang-github-openshift-oauth-proxy && \
    yum clean all

ENTRYPOINT   [ "/bin/oauth-proxy" ]

LABEL \
        com.redhat.component="golang-github-openshift-oauth-proxy-docker" \
        io.k8s.description="OpenShift OAuth Proxy." \
        maintainer="OpenShift Development <dev@lists.openshift.redhat.com>" \
        name="openshift3/oauth-proxy" \
        License="GPLv2+" \
        io.k8s.display-name="OpenShift OAuth Proxy" \
        version="2.3" \
        architecture="x86_64" \
        release="1.git57b68632" \
        vendor="Red Hat" \
        io.openshift.tags="oauth"

