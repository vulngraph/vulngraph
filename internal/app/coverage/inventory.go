package coverage

// indexMetaValues folds the measured metadata value splits into the index.
func (i *index) indexMetaValues() {
	i.metaValues = make(map[[3]string]uint64, len(i.facts.MetaValues))
	for _, mv := range i.facts.MetaValues {
		i.metaValues[[3]string{mv.AssetType, mv.Key, mv.Value}] += mv.Count
	}
}

// metaStageCount is a StageAssetMeta stage's count: fresh assets of its types
// whose MetaKey holds one of MetaValues. An absent key never counts — that is the
// whole point of a known-ness stage.
func (i *index) metaStageCount(st LineageStage) uint64 {
	var total uint64
	for _, t := range st.Types {
		for _, v := range st.MetaValues {
			total += i.metaValues[[3]string{t, st.MetaKey, v}]
		}
	}
	return total
}
