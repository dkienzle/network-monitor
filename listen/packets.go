package main

import (
	"crypto/sha1"
	"fmt"
)

type Histogram map[[sha1.Size]byte]int

func NewHistogram() Histogram {
	return make(Histogram, 1000)
}

func (histogram Histogram) tally(packet []byte) {
	sum := sha1.Sum(packet)
	histogram[sum] += 1
}

func (histogram Histogram) shortSummary() string {
	return fmt.Sprintf("%5d distinct frames", len(histogram))
}

func (histogram Histogram) writeDetail() {
	fmt.Printf("%d distinct frames\n", len(histogram))
	for _, num := range histogram {
		fmt.Printf("\t%5d\n", num)
	}
}
