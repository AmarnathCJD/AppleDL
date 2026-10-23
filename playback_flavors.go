package applemusic

// AudioFlavorOptions are inputs to Android's AssetFlavorSelector, not codec
// guarantees. BitrateEstimate is compared directly to the APK constants;
// -1 disables filtering. No unverified unit conversion is applied.
type AudioFlavorOptions struct {
	NetworkAllowed, WiFi, HighQualityCellular bool
	DataSaver, DebugBuild, ForceDataSaver     bool
	HLSEnabled, HLSConfigurationValid         bool
	BitrateEstimate                           int64
}

func PreferredAudioFlavors(o AudioFlavorOptions) []string {
	wifi := []string{"LWHQ", "LW", "SLW"}
	saver := []string{"SLW", "LW", "LWHQ"}
	var flavors []string
	filter := true
	switch {
	case o.DebugBuild && o.ForceDataSaver:
		flavors = saver
	case !o.NetworkAllowed:
		flavors, filter = wifi, false
	case o.WiFi || o.HighQualityCellular:
		flavors = wifi
	case o.DataSaver:
		flavors = saver
	default:
		flavors = []string{"LW", "SLW"}
	}
	if filter && o.BitrateEstimate != -1 {
		threshold := map[string]int64{"HQ": 320, "LWHQ": 320, "LW": 128, "SLW": 64}
		selected := make([]string, 0, len(flavors))
		for _, flavor := range flavors {
			if threshold[flavor] <= o.BitrateEstimate {
				selected = append(selected, flavor)
			}
		}
		flavors = selected
		if len(flavors) == 0 {
			flavors = []string{"SLW"}
		}
	}
	if o.HLSEnabled && o.HLSConfigurationValid {
		return append([]string{"HLS"}, flavors...)
	}
	return append(flavors, "HLS")
}
