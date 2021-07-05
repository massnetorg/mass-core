package massutil

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/massnetorg/mass-core/poc"
)

const bindingListFileMaxByteSize = 100 * poc.MiB

type BindingList struct {
	Plots        []BindingPlot `json:"plots"`
	TotalCount   uint64        `json:"total_count"`
	DefaultCount uint64        `json:"default_count"`
	ChiaCount    uint64        `json:"chia_count"`
}

func (list *BindingList) RemoveDuplicate() *BindingList {
	var newPlots = make([]BindingPlot, 0, len(list.Plots))
	var duplicate = make(map[string]bool, len(list.Plots))
	var counts = make(map[uint8]uint64, 2)
	for i, plot := range list.Plots {
		if duplicate[plot.String()] || !poc.IsValidProofType(poc.ProofType(plot.Type)) {
			continue
		}
		newPlots = append(newPlots, list.Plots[i])
		duplicate[plot.String()] = true
		counts[plot.Type] += 1
	}
	list.Plots = newPlots
	list.DefaultCount = counts[uint8(poc.ProofTypeDefault)]
	list.ChiaCount = counts[uint8(poc.ProofTypeChia)]
	list.TotalCount = list.DefaultCount + list.ChiaCount
	return list
}

func (list *BindingList) WriteToFile(filename string) error {
	list = list.RemoveDuplicate()
	data, err := json.Marshal(list)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(filename, data, 0644)
}

type BindingPlot struct {
	Target string `json:"target"`
	Type   uint8  `json:"type"`
	Size   uint8  `json:"size"`
}

func (plot BindingPlot) Equals(target BindingPlot) bool {
	return plot.Target == target.Target &&
		plot.Type == target.Type &&
		plot.Size == target.Size
}

func (plot BindingPlot) String() string {
	return fmt.Sprintf("%s/%d/%d", plot.Target, plot.Type, plot.Size)
}

func NewBindingListFromFile(filename string) (*BindingList, error) {
	fi, err := os.Stat(filename)
	if err != nil {
		return nil, err
	}
	if fi.Size() > bindingListFileMaxByteSize {
		return nil, errors.New("binding list file is larger than limit")
	}
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	list := &BindingList{}
	if err = json.Unmarshal(data, list); err != nil {
		return nil, err
	}
	return list, nil
}
