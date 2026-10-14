package scanner

import "time"

// ResponseHistory says how fast one dependency's fixes were adopted by the scanned project in the past: for each earlier
// advisory of the dependency that was fixed, the days between the fixed version's release and the first release of the
// project that required it. It is context shown next to a finding ("historically adopted comparable fixes in about 30
// days"), never part of the letter, and is absent when there is not enough history.
type ResponseHistory struct {
	Dependency string    `json:"dependency"` // module path of the dependency
	MedianDays int       `json:"median_days"`
	Samples    int       `json:"samples"` // fixes the median is taken over
	From       time.Time `json:"from"`    // earliest fix released among the samples
	To         time.Time `json:"to"`      // latest
}

// MinResponseSamples is how many adopted fixes a median needs before it is shown at all.
const MinResponseSamples = 3
