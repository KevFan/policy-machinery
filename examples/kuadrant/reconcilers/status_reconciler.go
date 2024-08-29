package reconcilers

import (
	"context"
	"fmt"
	"reflect"
	"strings"

	"github.com/google/go-cmp/cmp"
	"github.com/samber/lo"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/dynamic"

	"github.com/kuadrant/policy-machinery/controller"
	kuadrantv1beta3 "github.com/kuadrant/policy-machinery/examples/kuadrant/apis/v1beta3"
	"github.com/kuadrant/policy-machinery/machinery"
)

type StatusReconciler struct {
	Client *dynamic.DynamicClient
}

func NewStatusReconciler(client *dynamic.DynamicClient) *StatusReconciler {
	return &StatusReconciler{Client: client}
}

func (r *StatusReconciler) Reconcile(ctx context.Context, _ []controller.ResourceEvent, topology *machinery.Topology) {
	logger := controller.LoggerFromContext(ctx).WithName("status")

	// Get all authPolicies
	policies := topology.Policies().Items(func(object machinery.Object) bool {
		_, ok := object.(*kuadrantv1beta3.AuthPolicy)
		return ok
	})

	authPolicies := lo.Map(policies, func(item machinery.Policy, index int) *kuadrantv1beta3.AuthPolicy {
		return item.(*kuadrantv1beta3.AuthPolicy)
	})

	logger.Info("found authPolicies", "len", len(authPolicies))

	if len(authPolicies) == 0 {
		logger.Info("no authPolicies found")
		return
	}

	// Get all auth paths
	authPaths := pathsFromContext(ctx, authPathsKey)

	// for each auth policy
	for _, ap := range authPolicies {
		// find all the paths where the policy is in the path
		paths := lo.Filter(authPaths, func(item []machinery.Targetable, _ int) bool {
			for _, target := range item {
				for _, p := range target.Policies() {
					if p.GetLocator() == ap.GetLocator() {
						return true
					}
				}
			}
			return false
		})

		// If the policy is used in at least one path
		if len(paths) > 0 {
			logger.Info("found authPolicy in these paths", "paths", len(paths))

			// calculate the status based of the paths
			cond := r.aggregatePolicyConditions(ctx, ap, paths)

			// status changed
			if changed := meta.SetStatusCondition(&ap.Status.Conditions, cond); changed {
				un, err := controller.Destruct(ap)
				if err != nil {
					logger.Error(err, "failed to destruct authPolicy")
					return
				}

				resource := r.Client.Resource(kuadrantv1beta3.AuthPoliciesResource).Namespace(ap.Namespace)
				_, err = resource.UpdateStatus(ctx, un, metav1.UpdateOptions{})
				if err != nil {
					logger.Error(err, "failed to update authPolicy status")
					return
				}
			} else {
				logger.Info("status unchanged")
			}
		}
	}
}

func (r *StatusReconciler) aggregatePolicyConditions(ctx context.Context, ap *kuadrantv1beta3.AuthPolicy, paths [][]machinery.Targetable) metav1.Condition {
	cond := metav1.Condition{
		Type:   "Enforced",
		Status: metav1.ConditionTrue, // Assume all paths are enforced, adjust if any are not
		Reason: "Enforced",
	}

	var enforcedPaths []string
	var affectedPaths []string
	diff := "diff: "

	// For each path:
	// 1. Get the effective policy for path
	//   1.1. If the effective policy rules is the same as each rule in the compared policy -> fully enforced on this path
	//   1.2. If there is a difference -> not enforced on this path
	// 2. Condition
	//   2.1. If all paths are fully enforced -> condition true
	//   2.2. If one or more paths are affected -> conditions false

	for _, path := range paths {
		pathString := strings.Join(lo.Map(path, machinery.MapTargetableToLocatorFunc), "→")
		effectivePolicy := effectivePolicyForPath[*kuadrantv1beta3.AuthPolicy](ctx, path)

		// TODO: Check auth config for effective policy is ready

		fullyEnforced := true

		// Check if there is any difference in rules
		for k, v := range ap.Rules() {
			if !reflect.DeepEqual((*effectivePolicy).Rules()[k], v) {
				fullyEnforced = false
				diff = diff + cmp.Diff((*effectivePolicy).Rules()[k], v) + ", "
			}
		}
		if fullyEnforced {
			enforcedPaths = append(enforcedPaths, pathString)
		} else {
			cond.Status = metav1.ConditionFalse
			cond.Reason = "PolicyAffected"
			affectedPaths = append(affectedPaths, pathString)
		}
	}

	cond.Message = ""
	if len(enforcedPaths) > 0 {
		cond.Message = fmt.Sprintf("Fully enforcing policy on the following paths: %s", strings.Join(enforcedPaths, ", "))
	}

	if len(affectedPaths) > 0 {
		cond.Message = cond.Message + fmt.Sprintf("Policy rules has been affected on the following paths: %s, %s", strings.Join(affectedPaths, ", "), diff)
	}

	return cond
}
