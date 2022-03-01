package controller

import (
	"fmt"
	"strings"
)

// QName is a string type that represents a fully qualified name that includes the
// partition, namespace and service name.
type QName struct {
	partition string
	namespace string
	name      string
}

// NewQName creates a QName from the given partition, namespace and name.
// The partition and namespace are optional and can be set to the empty string
// if they are not applicable.
func NewQName(partition, namespace, name string) QName {
	return QName{partition: partition, namespace: namespace, name: name}
}

// QNameFromString creates a QName from the given slash-separated string.
func QNameFromString(s string) QName {
	var partition, namespace, name string

	parts := strings.SplitN(s, "/", 3)
	if len(parts) > 2 {
		partition = parts[0]
		namespace = parts[1]
		name = parts[2]
	} else {
		name = parts[len(parts)-1]
	}

	return QName{partition: partition, namespace: namespace, name: name}
}

// Partition returns the partition from the qualified name.
// It returns the empty string if the QName does not contain
// a partition and namespace.
func (q QName) Partition() string {
	if q.partition != "" && q.namespace != "" {
		return q.partition
	}
	return ""
}

// Namespace returns the namespace from the qualified name.
// It returns the empty string if the name does not contain
// a partition and namespace.
func (q QName) Namespace() string {
	if q.partition != "" && q.namespace != "" {
		return q.namespace
	}
	return ""
}

// Name returns the name from the qualified name.
// In the case where the QName does not include a partition or namespace
// the String() and Name() functions are equal.
func (q QName) Name() string {
	return q.name
}

// String returns a fully qualified name in the form
// 	<partition>/<namespace>/<name> If partitions are enabled.
// If partitions are not enabled it just returns the name portion.
func (q QName) String() string {
	if q.partition != "" && q.namespace != "" {
		return fmt.Sprintf("%s/%s/%s", q.partition, q.namespace, q.name)
	} else {
		return q.name
	}
}
