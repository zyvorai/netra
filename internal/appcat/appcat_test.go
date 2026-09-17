// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0
package appcat

import (
	"testing"

	"github.com/zyvorai/netra/internal/models"
)

func TestMatchCDN(t *testing.T) {
	agents := []models.AgentStatus{{
		AgentReport: models.AgentReport{
			Node: "n1",
			TLSMetadata: []models.TLSMetadataStat{{
				SNI: "d123.cloudfront.net", Handshakes: 4, Namespace: "ns", Pod: "p",
			}},
		},
	}}
	res := Match(agents, nil, 50)
	if res.Count != 1 || res.Hits[0].Category != CatCDN {
		t.Fatalf("%+v", res)
	}
}
