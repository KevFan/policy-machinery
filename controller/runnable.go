package controller

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/samber/lo"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/tools/cache"
)

type Runnable interface {
	Run(stopCh <-chan struct{})
	HasSynced() bool
}

type RunnableBuilder func(controller *Controller) Runnable

type RunnableBuilderOptions[T RuntimeObject] struct {
	LabelSelector string
	FieldSelector string
	Builder       func(resource schema.GroupVersionResource, namespace string, options ...RunnableBuilderOption[T]) RunnableBuilder
}

type RunnableBuilderOption[T RuntimeObject] func(*RunnableBuilderOptions[T])

func FilterResourcesByLabel[T RuntimeObject](selector string) RunnableBuilderOption[T] {
	return func(o *RunnableBuilderOptions[T]) {
		o.LabelSelector = selector
	}
}

func FilterResourcesByField[T RuntimeObject](selector string) RunnableBuilderOption[T] {
	return func(o *RunnableBuilderOptions[T]) {
		o.FieldSelector = selector
	}
}

func Builder[T RuntimeObject](builder func(resource schema.GroupVersionResource, namespace string, options ...RunnableBuilderOption[T]) RunnableBuilder) RunnableBuilderOption[T] {
	return func(o *RunnableBuilderOptions[T]) {
		o.Builder = builder
	}
}

func Watch[T RuntimeObject](resource schema.GroupVersionResource, namespace string, options ...RunnableBuilderOption[T]) RunnableBuilder {
	o := &RunnableBuilderOptions[T]{
		Builder: IncrementalInformer[T],
	}
	for _, f := range options {
		f(o)
	}
	return o.Builder(resource, namespace, options...)
}

func IncrementalInformer[T RuntimeObject](resource schema.GroupVersionResource, namespace string, options ...RunnableBuilderOption[T]) RunnableBuilder {
	o := &RunnableBuilderOptions[T]{}
	for _, f := range options {
		f(o)
	}
	return func(controller *Controller) Runnable {
		informer := cache.NewSharedInformer(
			&cache.ListWatch{
				ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
					if o.LabelSelector != "" {
						options.LabelSelector = o.LabelSelector
					}
					if o.FieldSelector != "" {
						options.FieldSelector = o.FieldSelector
					}
					return controller.client.Resource(resource).Namespace(namespace).List(context.Background(), options)
				},
				WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
					if o.LabelSelector != "" {
						options.LabelSelector = o.LabelSelector
					}
					if o.FieldSelector != "" {
						options.FieldSelector = o.FieldSelector
					}
					return controller.client.Resource(resource).Namespace(namespace).Watch(context.Background(), options)
				},
			},
			&unstructured.Unstructured{},
			time.Minute*10,
		)
		informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
			AddFunc: func(o any) {
				obj := o.(T)
				controller.add(resource, obj)
			},
			UpdateFunc: func(o, newO any) {
				oldObj := o.(T)
				newObj := newO.(T)
				controller.update(resource, oldObj, newObj)
			},
			DeleteFunc: func(o any) {
				obj := o.(T)
				controller.delete(resource, obj)
			},
		})
		informer.SetTransform(Restructure[T])
		return informer
	}
}

func StateReconciler[T RuntimeObject](resource schema.GroupVersionResource, namespace string, options ...RunnableBuilderOption[T]) RunnableBuilder {
	o := &RunnableBuilderOptions[T]{}
	for _, f := range options {
		f(o)
	}
	obj := new(T)
	kind := fmt.Sprintf("%T", obj)
	kind = kind[strings.LastIndex(kind, ".")+1:]
	return func(controller *Controller) Runnable {
		return &stateReconciler{
			controller: controller,
			listFunc: func() (schema.GroupKind, RuntimeObjects) {
				gk := schema.GroupKind{
					Group: resource.Group,
					Kind:  kind,
				}
				objs, err := controller.client.Resource(resource).Namespace(namespace).List(context.Background(), metav1.ListOptions{
					LabelSelector: o.LabelSelector,
					FieldSelector: o.FieldSelector,
				})
				if err != nil || len(objs.Items) == 0 {
					return gk, nil
				}
				return gk, lo.SliceToMap(objs.Items, func(o unstructured.Unstructured) (string, RuntimeObject) {
					obj, err := Restructure[T](&o)
					if err != nil {
						return "", nil
					}
					runtimeObj, ok := obj.(RuntimeObject)
					if !ok {
						return "", nil
					}
					return string(o.GetUID()), runtimeObj
				})
			},
		}
	}
}

type stateReconciler struct {
	controller *Controller
	listFunc   func() (schema.GroupKind, RuntimeObjects)
}

func (r *stateReconciler) Run(_ <-chan struct{}) {
	r.controller.listFuncs = append(r.controller.listFuncs)
}

func (r *stateReconciler) HasSynced() bool {
	return true
}

func Restructure[T any](obj any) (any, error) {
	unstructuredObj, ok := obj.(*unstructured.Unstructured)
	if !ok {
		return nil, fmt.Errorf("unexpected object type: %T", obj)
	}
	o := *new(T)
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(unstructuredObj.UnstructuredContent(), &o); err != nil {
		return nil, err
	}
	return o, nil
}

func Destruct[T any](obj T) (*unstructured.Unstructured, error) {
	u, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&obj)
	if err != nil {
		return nil, err
	}
	return &unstructured.Unstructured{Object: u}, nil
}
