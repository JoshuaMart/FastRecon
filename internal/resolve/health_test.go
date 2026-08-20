package resolve

import (
	"context"
	"slices"
	"testing"
	"time"
)

func withCheck(t *testing.T, fn func(resolver string, timeout time.Duration) string) {
	t.Helper()
	original := checkOne
	checkOne = fn
	t.Cleanup(func() { checkOne = original })
}

func TestCheckResolversDropsTheBadOnes(t *testing.T) {
	withCheck(t, func(resolver string, _ time.Duration) string {
		switch resolver {
		case "2.2.2.2:53":
			return dropHijacker
		case "3.3.3.3:53":
			return dropUnreachable
		default:
			return ""
		}
	})

	res := CheckResolvers(context.Background(), []string{"1.1.1.1:53", "2.2.2.2:53", "3.3.3.3:53", "4.4.4.4:53"}, HealthOptions{
		Concurrency: 4,
		Logger:      discardLogger(),
	})

	slices.Sort(res.Good)
	if !slices.Equal(res.Good, []string{"1.1.1.1:53", "4.4.4.4:53"}) {
		t.Errorf("good = %v, want the two healthy resolvers", res.Good)
	}
	if len(res.Dropped) != 2 {
		t.Fatalf("dropped = %v, want 2", res.Dropped)
	}
	byResolver := map[string]string{}
	for _, d := range res.Dropped {
		byResolver[d.Resolver] = d.Reason
	}
	if byResolver["2.2.2.2:53"] != dropHijacker {
		t.Errorf("reasons = %v, want the hijacker named as such", byResolver)
	}
	if res.Unchecked != 0 {
		t.Errorf("unchecked = %d, want 0", res.Unchecked)
	}
}

// Resolvers the budget did not reach are kept and counted. Dropping them
// would silently shrink the pool; claiming they passed would be a lie.
func TestCheckResolversKeepsAndCountsWhatItCouldNotCheck(t *testing.T) {
	withCheck(t, func(string, time.Duration) string {
		time.Sleep(50 * time.Millisecond)
		return dropUnreachable
	})

	resolvers := make([]string, 200)
	for i := range resolvers {
		resolvers[i] = "1.1.1." + string(rune('0'+i%10)) + ":53"
	}

	res := CheckResolvers(context.Background(), resolvers, HealthOptions{
		Budget:      80 * time.Millisecond,
		Concurrency: 2,
		Logger:      discardLogger(),
	})

	if res.Unchecked == 0 {
		t.Fatal("nothing was reported unchecked despite an exhausted budget")
	}
	if len(res.Good)+len(res.Dropped) != len(resolvers) {
		t.Errorf("accounting lost resolvers: %d good + %d dropped != %d", len(res.Good), len(res.Dropped), len(resolvers))
	}
	if len(res.Good) < res.Unchecked {
		t.Error("unchecked resolvers must be kept in the pool")
	}
}

func TestCheckResolversHandlesAnEmptyPool(t *testing.T) {
	res := CheckResolvers(context.Background(), nil, HealthOptions{Logger: discardLogger()})
	if len(res.Good) != 0 || len(res.Dropped) != 0 {
		t.Errorf("res = %+v, want everything empty", res)
	}
}
