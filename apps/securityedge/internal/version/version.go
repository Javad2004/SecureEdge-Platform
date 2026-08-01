package version

import (
	"fmt"
	"runtime"
)

const Name = "SecurityEdge"

var (
	Version   = "development"
	Commit    = "development"
	BuildTime = "unknown"
)

type BuildInfo struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuildTime string `json:"build_time"`
	GoVersion string `json:"go_version"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
}

func Info() BuildInfo {
	return BuildInfo{
		Name: Name, Version: Version, Commit: Commit, BuildTime: BuildTime,
		GoVersion: runtime.Version(), OS: runtime.GOOS, Arch: runtime.GOARCH,
	}
}

func String() string {
	i := Info()
	return fmt.Sprintf("%s %s (commit=%s, built=%s, go=%s, %s/%s)", i.Name, i.Version, i.Commit, i.BuildTime, i.GoVersion, i.OS, i.Arch)
}
