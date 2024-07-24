package controller

import (
	"github.com/samber/lo"
	core "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/kuadrant/policy-machinery/machinery"
)

func newGatewayAPITopologyBuilder(policyKinds, objectKinds []schema.GroupKind, objectLinks []RuntimeLinkFunc) *gatewayAPITopologyBuilder {
	return &gatewayAPITopologyBuilder{
		policyKinds: policyKinds,
		objectKinds: objectKinds,
		objectLinks: objectLinks,
	}
}

type gatewayAPITopologyBuilder struct {
	policyKinds []schema.GroupKind
	objectKinds []schema.GroupKind
	objectLinks []RuntimeLinkFunc
}

func (t *gatewayAPITopologyBuilder) Build(objs Store) *machinery.Topology {
	gatewayClasses := lo.FilterMap(lo.Values(objs[schema.GroupKind{Group: gwapiv1.GroupVersion.Group, Kind: "GatewayClass"}]), func(obj RuntimeObject, _ int) (*gwapiv1.GatewayClass, bool) {
		gc, ok := obj.(*gwapiv1.GatewayClass)
		if !ok {
			return nil, false
		}
		return gc, true
	})

	gateways := lo.FilterMap(lo.Values(objs[schema.GroupKind{Group: gwapiv1.GroupVersion.Group, Kind: "Gateway"}]), func(obj RuntimeObject, _ int) (*gwapiv1.Gateway, bool) {
		gw, ok := obj.(*gwapiv1.Gateway)
		if !ok {
			return nil, false
		}
		return gw, true
	})

	httpRoutes := lo.FilterMap(lo.Values(objs[schema.GroupKind{Group: gwapiv1.GroupVersion.Group, Kind: "HTTPRoute"}]), func(obj RuntimeObject, _ int) (*gwapiv1.HTTPRoute, bool) {
		httpRoute, ok := obj.(*gwapiv1.HTTPRoute)
		if !ok {
			return nil, false
		}
		return httpRoute, true
	})

	services := lo.FilterMap(lo.Values(objs[schema.GroupKind{Group: core.GroupName, Kind: "Service"}]), func(obj RuntimeObject, _ int) (*core.Service, bool) {
		service, ok := obj.(*core.Service)
		if !ok {
			return nil, false
		}
		return service, true
	})

	linkFuncs := lo.Map(t.objectLinks, func(linkFunc RuntimeLinkFunc, _ int) machinery.LinkFunc {
		return linkFunc(objs)
	})

	opts := []machinery.GatewayAPITopologyOptionsFunc{
		machinery.WithGatewayClasses(gatewayClasses...),
		machinery.WithGateways(gateways...),
		machinery.WithHTTPRoutes(httpRoutes...),
		machinery.WithServices(services...),
		machinery.ExpandGatewayListeners(),
		machinery.ExpandHTTPRouteRules(),
		machinery.ExpandServicePorts(),
		machinery.WithGatewayAPITopologyLinks(linkFuncs...),
	}

	for i := range t.policyKinds {
		policyKind := t.policyKinds[i]
		policies := lo.FilterMap(lo.Values(objs[policyKind]), func(obj RuntimeObject, _ int) (machinery.Policy, bool) {
			policy, ok := obj.(machinery.Policy)
			return policy, ok
		})

		opts = append(opts, machinery.WithGatewayAPITopologyPolicies(policies...))
	}

	for i := range t.objectKinds {
		objectKind := t.objectKinds[i]
		objects := lo.FilterMap(lo.Values(objs[objectKind]), func(obj RuntimeObject, _ int) (machinery.Object, bool) {
			object, ok := obj.(machinery.Object)
			if ok {
				return object, ok
			}
			return &Object{obj}, true
		})

		opts = append(opts, machinery.WithGatewayAPITopologyObjects(objects...))
	}

	return machinery.NewGatewayAPITopology(opts...)
}

type Object struct {
	RuntimeObject RuntimeObject
}

func (g *Object) GroupVersionKind() schema.GroupVersionKind {
	return g.RuntimeObject.GetObjectKind().GroupVersionKind()
}

func (g *Object) SetGroupVersionKind(schema.GroupVersionKind) {}

func (g *Object) GetNamespace() string {
	return g.RuntimeObject.GetNamespace()
}

func (g *Object) GetName() string {
	return g.RuntimeObject.GetName()
}

func (g *Object) GetURL() string {
	return machinery.UrlFromObject(g)
}
