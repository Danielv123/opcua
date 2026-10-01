package securechannel_test

import (
	"math"
	"testing"

	"github.com/awcullen/opcua/internal/securechannel"
	"github.com/awcullen/opcua/ua"
)

func TestSequenceNumberValidator(t *testing.T) {
	type step struct {
		n  uint32
		ok bool
	}
	cases := []struct {
		name  string
		steps []step
	}{
		{"FirstAnyValue", []step{{123456, true}, {123457, true}}},
		{"FirstZero", []step{{0, true}, {1, true}}},
		{"Increment", []step{{1, true}, {2, true}, {3, true}, {4, true}}},
		{"Replay", []step{{1, true}, {2, true}, {2, false}}},
		{"ReplayOlder", []step{{1, true}, {2, true}, {3, true}, {1, false}}},
		{"OutOfOrder", []step{{10, true}, {12, false}, {11, true}}},
		{"Gap", []step{{10, true}, {11, true}, {13, false}}},
		{"RejectedChunkDoesNotAdvance", []step{{10, true}, {20, false}, {21, false}, {11, true}}},
		{"RolloverFromMax", []step{{math.MaxUint32 - 1, true}, {math.MaxUint32, true}, {1, true}, {2, true}}},
		{"RolloverFromMaxToZero", []step{{math.MaxUint32, true}, {0, true}, {1, true}}},
		{"RolloverWithinWindow", []step{{math.MaxUint32 - 500, true}, {1023, true}, {1024, true}}},
		{"RolloverFromWindowStart", []step{{math.MaxUint32 - 1024, true}, {5, true}}},
		{"ContinueAboveWindowStart", []step{{math.MaxUint32 - 1024, true}, {math.MaxUint32 - 1023, true}}},
		{"RolloverBeforeWindow", []step{{math.MaxUint32 - 1025, true}, {1, false}, {0, false}}},
		{"RolloverTooLarge", []step{{math.MaxUint32, true}, {1024, false}, {5000, false}}},
		{"RolloverReplay", []step{{math.MaxUint32, true}, {1, true}, {math.MaxUint32, false}, {1, false}, {2, true}}},
		{"BackwardsBelowWindow", []step{{2000, true}, {1, false}}},
	}
	for _, c := range cases {
		var v securechannel.SequenceNumberValidator
		for i, s := range c.steps {
			err := v.Validate(s.n)
			if s.ok && err != nil {
				t.Errorf("%s: step %d: Validate(%d) = %v, want nil", c.name, i, s.n, err)
			}
			if !s.ok && err != ua.BadSequenceNumberInvalid {
				t.Errorf("%s: step %d: Validate(%d) = %v, want %v", c.name, i, s.n, err, ua.BadSequenceNumberInvalid)
			}
		}
	}
}
