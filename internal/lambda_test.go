package internal

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTransform(t *testing.T) {
	tests := []struct {
		name                      string
		fastlyCidrs               []string
		securityGroupIngressCidrs []string
		cidrsToAdd                []string
		cidrsToRemove             []string
	}{
		{
			name:                      "Join A + Join B",
			fastlyCidrs:               []string{"10.0.0.0/8"},
			securityGroupIngressCidrs: []string{"172.0.0.0/8"},
			cidrsToAdd:                []string{"10.0.0.0/8"},
			cidrsToRemove:             []string{"172.0.0.0/8"},
		},
		{
			name:                      "Join A",
			fastlyCidrs:               []string{"10.0.0.0/8"},
			securityGroupIngressCidrs: []string{},
			cidrsToAdd:                []string{"10.0.0.0/8"},
			cidrsToRemove:             []string(nil),
		},
		{
			name:                      "Join B",
			fastlyCidrs:               []string{"10.0.0.0/8"},
			securityGroupIngressCidrs: []string{"10.0.0.0/8", "172.0.0.0/8"},
			cidrsToAdd:                []string(nil),
			cidrsToRemove:             []string{"172.0.0.0/8"},
		},
		{
			name:                      "No Change",
			fastlyCidrs:               []string{"10.0.0.0/8"},
			securityGroupIngressCidrs: []string{"10.0.0.0/8"},
			cidrsToAdd:                []string(nil),
			cidrsToRemove:             []string(nil),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			add, remove := transform(test.fastlyCidrs, test.securityGroupIngressCidrs)
			assert.EqualValues(t, add, test.cidrsToAdd)
			assert.EqualValues(t, remove, test.cidrsToRemove)
		})
	}
}
