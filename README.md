Continuous integration | License
 -----------------------|--------
![Continuous integration](https://github.com/kubewarden/readonly-root-filesystem-psp-policy/workflows/Continuous%20integration/badge.svg) | [![License: Apache 2.0](https://img.shields.io/badge/License-Apache2.0-brightgreen.svg)](https://opensource.org/licenses/Apache-2.0)


This Kubewarden Policy is a replacement for the Kubernetes Pod Security Policy
that enforces the usage of [`ReadOnlyRootFilesystems`](https://kubernetes.io/docs/concepts/policy/pod-security-policy/#volumes-and-file-systems).

# How the policy works

The policy inspects the `securityContext` of each container defined inside of
a Pod and ensures all the containers have the `readOnlyRootFilesystem` attribute
set to `true`.

The policy checks the both the `pod.spec.containers` and the init containers
too.

Containers that do not have a `securityContext` defined are rejected too.
That happens because, by default, the root filesystem of a container is
considered to be writable.

Ephemeral containers are not checked because, by Kubernetes definition, they
cannot have a `securityContext`.

# Configuration

The policy doesn't have any configuration.

# Obtain policy

The policy is automatically published as an OCI artifact inside of
[this](https://github.com/orgs/kubewarden/packages/container/package/policies%2Freadonly-root-filesystem-psp-policy)
container registry.

# Using the policy

The easiest way to use this policy is through the [kubewarden-controller](https://github.com/kubewarden/kubewarden-controller).
